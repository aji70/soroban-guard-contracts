//! VULNERABLE: Unsafe Storage Writes
//!
//! A user-profile / KYC registry contract where any caller can overwrite
//! any account's stored data via a public `set_profile()` function.
//! There is no auth check tying the write to the account being modified.
//!
//! VULNERABILITY: `set_profile` writes to persistent storage keyed by an
//! arbitrary `Address` argument without verifying the caller owns that address.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
pub struct Profile {
    pub display_name: String,
    pub kyc_level: u32,
}

#[contracttype]
pub enum DataKey {
    Profile(Address),
}

#[contract]
pub struct ProfileRegistry;

#[contractimpl]
impl ProfileRegistry {
    /// VULNERABLE: `account` is an arbitrary parameter — the caller can pass
    /// any address and overwrite that account's profile without owning it.
    pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
        // ❌ Missing: account.require_auth();

        let profile = Profile {
            display_name,
            kyc_level,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Profile(account), &profile);
    }

    /// Returns the stored profile for `account`, or `None` if not set.
    pub fn get_profile(env: Env, account: Address) -> Option<Profile> {
        env.storage().persistent().get(&DataKey::Profile(account))
    }

    /// VULNERABLE: same pattern — anyone can wipe any account's profile.
    /// Missing `account.require_auth()` — any caller can delete any account's data.
    ///
    /// # Vulnerability
    /// Missing auth: `account.require_auth()`. Impact: data destruction for any account.
    pub fn delete_profile(env: Env, account: Address) {
        // ❌ Missing: account.require_auth();
        env.storage()
            .persistent()
            .remove(&DataKey::Profile(account));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    #[test]
    fn test_set_and_get_profile() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProfileRegistry);
        let client = ProfileRegistryClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let name = String::from_str(&env, "Alice");
        client.set_profile(&alice, &name, &1);

        let profile = client.get_profile(&alice).unwrap();
        assert_eq!(profile.kyc_level, 1);
    }

    /// Demonstrates the vulnerability: bob overwrites alice's profile without auth.
    #[test]
    fn test_anyone_can_overwrite_any_profile() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProfileRegistry);
        let client = ProfileRegistryClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let alice_name = String::from_str(&env, "Alice");
        let fake_name = String::from_str(&env, "Hacked");

        client.set_profile(&alice, &alice_name, &2);

        // No auth needed — attacker passes alice's address and overwrites her data.
        client.set_profile(&alice, &fake_name, &0);

        let profile = client.get_profile(&alice).unwrap();
        assert_eq!(profile.kyc_level, 0);
    }

    #[test]
    fn test_delete_profile() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProfileRegistry);
        let client = ProfileRegistryClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let name = String::from_str(&env, "Alice");
        client.set_profile(&alice, &name, &1);
        client.delete_profile(&alice);

        assert!(client.get_profile(&alice).is_none());
    }
}
