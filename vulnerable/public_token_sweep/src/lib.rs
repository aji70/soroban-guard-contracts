//! VULNERABLE: Public Token Sweep Without Admin Authorization
//!
//! A contract that holds tokens and exposes a sweep function intended for
//! recovering accidentally transferred tokens. However, the sweep function
//! lacks admin authorization checks, allowing any caller to drain arbitrary
//! token balances from the contract to themselves.
//!
//! VULNERABILITY: `sweep_tokens` does not verify that the caller is an admin
//! or authorized party. Any address can call it and transfer contract-held
//! tokens to their own address.
//!
//! SECURE MIRROR: `secure::SecureTokenVault` requires admin authorization
//! before allowing token sweeps, preventing unauthorized drains.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    TokenBalance(Address), // Track token balances held by contract
}

#[contract]
pub struct VulnerableTokenVault;

#[contractimpl]
impl VulnerableTokenVault {
    /// Initialize the vault with an admin. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Deposit tokens into the vault. Requires caller auth.
    /// In a real scenario, tokens would be transferred via token contract.
    pub fn deposit(env: Env, depositor: Address, token: Address, amount: i128) {
        depositor.require_auth();
        
        let key = DataKey::TokenBalance(token.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &(current + amount));
    }

    /// VULNERABLE: sweep tokens from contract custody to caller without admin check.
    /// Any caller can drain arbitrary token balances to themselves.
    ///
    /// # Vulnerability
    /// Missing admin authorization check. Impact: anyone can sweep contract tokens.
    pub fn sweep_tokens(env: Env, token: Address, recipient: Address, amount: i128) {
        // ❌ Missing: admin authorization check
        // recipient.require_auth() is also missing - caller can specify any recipient

        let key = DataKey::TokenBalance(token.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        
        if balance < amount {
            panic!("insufficient balance");
        }

        let new_balance = balance - amount;
        env.storage().persistent().set(&key, &new_balance);

        // In a real implementation, this would call token.transfer()
        // For this fixture, we just track the balance change
    }

    /// Returns the token balance held by the contract.
    pub fn get_token_balance(env: Env, token: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TokenBalance(token))
            .unwrap_or(0)
    }

    /// Returns the admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableTokenVaultClient<'static>, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableTokenVault);
        let client = VulnerableTokenVaultClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let token = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        (env, client, admin, token)
    }

    /// Demonstrates the vulnerability: any caller can sweep tokens without authorization.
    #[test]
    fn test_anyone_can_sweep_tokens() {
        let (env, client, _admin, token) = setup();

        let depositor = Address::generate(&env);
        let attacker = Address::generate(&env);

        // Depositor adds tokens to the vault
        client.deposit(&depositor, &token, &5000);
        assert_eq!(client.get_token_balance(&token), 5000);

        // Attacker sweeps tokens to themselves — no admin check!
        client.sweep_tokens(&token, &attacker, &5000);

        assert_eq!(client.get_token_balance(&token), 0);
    }

    /// Multiple attackers can drain different token types.
    #[test]
    fn test_multiple_attackers_drain_different_tokens() {
        let (env, client, _admin, token1) = setup();

        let token2 = Address::generate(&env);
        let depositor = Address::generate(&env);
        let attacker1 = Address::generate(&env);
        let attacker2 = Address::generate(&env);

        client.deposit(&depositor, &token1, &1000);
        client.deposit(&depositor, &token2, &2000);

        client.sweep_tokens(&token1, &attacker1, &1000);
        client.sweep_tokens(&token2, &attacker2, &2000);

        assert_eq!(client.get_token_balance(&token1), 0);
        assert_eq!(client.get_token_balance(&token2), 0);
    }

    /// Attacker can sweep partial amounts repeatedly.
    #[test]
    fn test_attacker_can_sweep_partial_amounts() {
        let (env, client, _admin, token) = setup();

        let depositor = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.deposit(&depositor, &token, &10000);

        client.sweep_tokens(&token, &attacker, &3000);
        assert_eq!(client.get_token_balance(&token), 7000);

        client.sweep_tokens(&token, &attacker, &3000);
        assert_eq!(client.get_token_balance(&token), 4000);

        client.sweep_tokens(&token, &attacker, &4000);
        assert_eq!(client.get_token_balance(&token), 0);
    }

    /// Secure version: sweep requires admin authorization.
    #[test]
    fn test_secure_requires_admin_auth() {
        use crate::secure::SecureTokenVaultClient;
        use soroban_sdk::IntoVal;

        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureTokenVault);
        let client = SecureTokenVaultClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let token = Address::generate(&env);
        let depositor = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.deposit(&depositor, &token, &5000);

        // Only mock attacker auth — admin has NOT authorized this call.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &attacker,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "sweep_tokens",
                args: (token.clone(), attacker.clone(), 5000_i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.sweep_tokens(&token, &attacker, &5000);
        }));

        assert!(result.is_err(), "must reject without admin authorization");
        assert_eq!(
            client.get_token_balance(&token),
            5000,
            "tokens must remain in vault"
        );
    }
}
