//! VULNERABLE: Zero-Amount Deposit
//!
//! A vault contract where `deposit` accepts `amount == 0` without error.
//! This writes a zero-balance entry to persistent storage, wasting ledger
//! space and confusing any accounting logic that assumes stored entries
//! always hold a positive balance.
//!
//! VULNERABILITY: No guard on the `amount` parameter — a caller can deposit
//! zero tokens and still create a storage entry for their address.
//!
//! SECURE MIRROR: `secure::SecureVault` panics with "deposit must be positive"
//! when `amount == 0`, preventing empty entries from ever being written.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// VULNERABLE: `amount` is written to storage even when it is zero,
    /// creating a junk entry that wastes ledger space.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ❌ Missing: assert!(amount > 0, "deposit must be positive");
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Returns the current balance of `user`, defaulting to 0.
    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Normal deposit stores the correct balance.
    #[test]
    fn test_normal_deposit() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &id);

        let user = Address::generate(&env);
        client.deposit(&user, &500);
        assert_eq!(client.balance(&user), 500);
    }

    /// DEMONSTRATES VULNERABILITY: zero deposit succeeds and writes a
    /// zero-balance entry to persistent storage.
    #[test]
    fn test_zero_deposit_creates_storage_entry() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &id);

        let user = Address::generate(&env);

        // No entry exists yet.
        assert_eq!(client.balance(&user), 0);

        // Zero deposit should be rejected but isn't — it writes a 0 entry.
        client.deposit(&user, &0);

        // Entry now exists in storage with a zero balance.
        assert!(
            env.as_contract(&id, || {
                env.storage()
                    .persistent()
                    .has(&DataKey::Balance(user.clone()))
            }),
            "zero deposit must not create a storage entry, but it did"
        );
        assert_eq!(client.balance(&user), 0);
    }

    /// Secure version rejects zero deposits with a panic.
    #[test]
    #[should_panic(expected = "deposit must be positive")]
    fn test_secure_rejects_zero_deposit() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let user = Address::generate(&env);
        client.deposit(&user, &0);
    }
}
