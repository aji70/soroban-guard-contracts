//! VULNERABLE: Unprotected Delete
//!
//! A data registry contract where any caller can delete any account's
//! persistent storage entry via `delete_entry()` without owning that address.
//!
//! VULNERABILITY: `delete_entry` removes persistent storage keyed by an
//! arbitrary `Address` argument without calling `account.require_auth()`.
//! An attacker can wipe any account's data with no authorization.
//!
//! SECURE MIRROR: See `secure/protected_admin` which enforces `account.require_auth()`
//! before any mutating storage operation.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

#[contracttype]
pub enum DataKey {
    Entry(Address),
}

#[contract]
pub struct DataRegistry;

#[contractimpl]
impl DataRegistry {
    /// Store a string value for `account`. No auth check — intentionally unprotected for test setup.
    pub fn set_entry(env: Env, account: Address, value: String) {
        env.storage()
            .persistent()
            .set(&DataKey::Entry(account), &value);
    }

    /// Returns the stored entry for `account`, or `None` if absent.
    pub fn get_entry(env: Env, account: Address) -> Option<String> {
        env.storage().persistent().get(&DataKey::Entry(account))
    }

    /// VULNERABLE: `account` is an arbitrary parameter — the caller can pass
    /// any address and delete that account's data without owning it.
    pub fn delete_entry(env: Env, account: Address) {
        // ❌ Missing: account.require_auth();
        env.storage().persistent().remove(&DataKey::Entry(account));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, DataRegistryClient<'static>) {
        let env = Env::default();
        let contract_id = env.register_contract(None, DataRegistry);
        let client = DataRegistryClient::new(&env, &contract_id);
        (env, client)
    }

    /// Normal path: an account deletes its own entry.
    #[test]
    fn test_owner_can_delete_own_entry() {
        let (env, client) = setup();
        let alice = Address::generate(&env);
        let value = String::from_str(&env, "alice_data");

        client.set_entry(&alice, &value);
        assert!(client.get_entry(&alice).is_some());

        client.delete_entry(&alice);
        assert!(client.get_entry(&alice).is_none());
    }

    /// Demonstrates the vulnerability: attacker deletes alice's entry without auth.
    #[test]
    fn test_attacker_can_delete_any_entry() {
        let (env, client) = setup();
        let alice = Address::generate(&env);
        let _attacker = Address::generate(&env);
        let value = String::from_str(&env, "alice_data");

        client.set_entry(&alice, &value);
        assert!(client.get_entry(&alice).is_some());

        // No auth required — attacker passes alice's address and wipes her data.
        client.delete_entry(&alice);

        assert!(client.get_entry(&alice).is_none());
    }

    /// After deletion, get_entry returns None.
    #[test]
    fn test_get_returns_none_after_delete() {
        let (env, client) = setup();
        let alice = Address::generate(&env);
        let value = String::from_str(&env, "some_value");

        client.set_entry(&alice, &value);
        client.delete_entry(&alice);

        assert_eq!(client.get_entry(&alice), None);
    }
}
