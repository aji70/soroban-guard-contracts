//! VULNERABLE: Missing Authorization
//!
//! A simple token contract where `transfer()` mutates balances without
//! calling `env.require_auth()`. Any account can drain any other account's
//! balance by crafting a transaction — no signature required.
//!
//! VULNERABILITY: Missing `env.require_auth(&from)` before state mutation.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    /// Mint tokens to `to`. In a real contract this would be admin-gated; here it is also
    /// unprotected, but the primary vulnerability is in `transfer`.
    ///
    /// # Vulnerability
    /// No admin auth check — any caller can mint arbitrary tokens.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// VULNERABLE: transfers `amount` from `from` to `to` without verifying
    /// that the caller is `from`. No `from.require_auth()` call.
    // The missing require_auth is intentional — this contract demonstrates the vulnerability.
    #[allow(clippy::needless_pass_by_value)]
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        // ❌ Missing: from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        // No auth check — anyone can call this and move funds out of `from`
        env.storage()
            .persistent()
            .set(&from_key, &(from_balance - amount));
        env.storage()
            .persistent()
            .set(&to_key, &(to_balance + amount));

        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

    /// Returns the current balance of `account`. Defaults to 0 if no entry exists.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_mint_and_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        client.mint(&alice, &1000);
        assert_eq!(client.balance(&alice), 1000);
    }

    /// Demonstrates the vulnerability: bob transfers from alice without auth.
    #[test]
    fn test_transfer_requires_no_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &500);

        // No mock_auths needed — the contract never checks auth.
        // This call succeeds even though bob is the invoker, not alice.
        client.transfer(&alice, &bob, &500);

        assert_eq!(client.balance(&alice), 0);
        assert_eq!(client.balance(&bob), 500);
    }

    #[test]
    fn test_transfer_updates_both_balances() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &1000);
        client.mint(&bob, &200);
        client.transfer(&alice, &bob, &300);

        assert_eq!(client.balance(&alice), 700);
        assert_eq!(client.balance(&bob), 500);
    }
}
