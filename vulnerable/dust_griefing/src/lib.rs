//! VULNERABLE: Dust Griefing via Unrestricted Deposits
//!
//! A vault contract where `deposit()` accepts any positive amount, including 1.
//! An attacker can create thousands of 1-unit deposits across many addresses,
//! bloating persistent storage and inflating TTL extension costs for everyone.
//!
//! VULNERABILITY: No minimum deposit threshold — `assert!(amount >= MIN_DEPOSIT)`
//! is never enforced, so dust deposits are accepted unconditionally.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const MIN_DEPOSIT: i128 = 1_000;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

pub fn get_balance(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

pub fn set_balance(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(user.clone()), &amount);
}

#[contract]
pub struct DustGriefingVault;

#[contractimpl]
impl DustGriefingVault {
    /// VULNERABLE: accepts any positive `amount` including dust (e.g. 1 unit).
    /// Creates a storage entry for every depositor regardless of amount, enabling griefing.
    ///
    /// # Vulnerability
    /// Missing `assert!(amount >= MIN_DEPOSIT)`. Impact: ledger bloat via mass dust deposits.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ❌ Missing: assert!(amount >= MIN_DEPOSIT);
        let bal = get_balance(&env, &user);
        set_balance(&env, &user, bal + amount);
    }

    /// Returns the balance of `user`, defaulting to 0.
    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureVaultClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, DustGriefingVault);
        (env, id)
    }

    #[test]
    fn test_normal_deposit_works() {
        let (env, id) = setup();
        let client = DustGriefingVaultClient::new(&env, &id);
        let alice = Address::generate(&env);

        client.deposit(&alice, &5_000);
        assert_eq!(client.balance(&alice), 5_000);
    }

    /// Demonstrates the vulnerability: a dust deposit of 1 unit is accepted.
    #[test]
    fn test_dust_deposit_succeeds() {
        let (env, id) = setup();
        let client = DustGriefingVaultClient::new(&env, &id);
        let attacker = Address::generate(&env);

        // 1-unit deposit should be rejected by a secure contract, but succeeds here.
        client.deposit(&attacker, &1);
        assert_eq!(client.balance(&attacker), 1);
    }

    /// Secure version rejects amounts below MIN_DEPOSIT.
    #[test]
    #[should_panic]
    fn test_secure_rejects_dust() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        let attacker = Address::generate(&env);

        client.deposit(&attacker, &1);
    }

    #[test]
    fn test_secure_accepts_valid_deposit() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        let alice = Address::generate(&env);

        client.deposit(&alice, &MIN_DEPOSIT);
        assert_eq!(client.balance(&alice), MIN_DEPOSIT);
    }
}
