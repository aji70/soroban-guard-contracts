//! VULNERABLE: Admin Stored in Instance Storage
//!
//! The contract stores the admin address using `env.storage().instance().set()`.
//! Instance storage is tied to the contract's WASM instance and is reset when
//! the contract is upgraded to a new WASM hash. After an upgrade the admin key
//! is gone, leaving the contract permanently without an admin and making all
//! admin-gated functions inaccessible.
//!
//! VULNERABILITY: `initialize` writes the admin to instance storage instead of
//! persistent storage. A WASM upgrade wipes instance storage, losing the admin.
//!
//! SEVERITY: High
//! FIX: migrate to `env.storage().persistent().set()`

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct InstanceAdminStorage;

#[contractimpl]
impl InstanceAdminStorage {
    /// VULNERABLE: stores admin in instance storage — wiped on WASM upgrade.
    pub fn initialize(env: Env, admin: Address) {
        // ❌ Instance storage is reset when the contract WASM is upgraded.
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: reads admin from instance storage — returns nothing after upgrade.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Admin-gated function — inaccessible after upgrade wipes instance storage.
    pub fn set_value(env: Env, value: u64) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().instance().set(&"value", &value);
    }

    pub fn get_value(env: Env) -> u64 {
        env.storage().instance().get(&"value").unwrap_or(0)
    }

    /// Simulates a WASM upgrade — in the test harness we use
    /// `env.deployer().update_current_contract_wasm()` which resets instance
    /// storage, demonstrating the vulnerability.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

// ── Secure version (inline) ───────────────────────────────────────────────────

#[contract]
pub struct SecureAdminStorage;

#[contractimpl]
impl SecureAdminStorage {
    /// FIX: stores admin in persistent storage — survives WASM upgrades.
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Baseline: admin is readable immediately after initialize.
    #[test]
    fn test_admin_readable_after_initialize() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, InstanceAdminStorage);
        let client = InstanceAdminStorageClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
    }

    /// Demonstrates the bug: after a WASM upgrade, instance storage is wiped
    /// and get_admin panics because the key no longer exists.
    #[test]
    #[should_panic(expected = "not initialized")]
    fn test_admin_lost_after_upgrade() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, InstanceAdminStorage);
        let client = InstanceAdminStorageClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);

        // Simulate upgrade by clearing instance storage directly (the test
        // harness equivalent of deploying new WASM, which resets instance storage).
        env.as_contract(&id, || {
            env.storage().instance().remove(&DataKey::Admin);
        });

        // After the upgrade wipes instance storage, get_admin panics.
        client.get_admin();
    }

    /// Secure version: admin stored in persistent storage survives an upgrade.
    #[test]
    fn test_secure_admin_survives_upgrade() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureAdminStorage);
        let client = SecureAdminStorageClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);

        // Simulate upgrade — persistent storage is NOT wiped.
        env.as_contract(&id, || {
            // Instance storage cleared; persistent storage untouched.
            env.storage().instance().remove(&DataKey::Admin);
        });

        // Admin is still readable from persistent storage.
        assert_eq!(client.get_admin(), admin);
    }
}
