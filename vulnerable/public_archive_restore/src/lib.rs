//! VULNERABLE: Public Archive Restore
//!
//! A registry contract that supports an archive/restore lifecycle for records.
//! The `archive` function is correctly admin-gated, but `restore` performs no
//! authorization check at all — any caller can reactivate a deprecated or
//! malicious record.
//!
//! VULNERABILITY: `restore` flips the `active` flag back to `true` without
//! calling `admin.require_auth()`, so any account can undo an admin archive.
//!
//! Severity: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// Whether the record identified by `Address` is currently active.
    Active(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableRegistry;

#[contractimpl]
impl VulnerableRegistry {
    /// One-time initialisation — stores the admin address.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Register a new record as active. Requires admin auth.
    pub fn register(env: Env, record: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Active(record.clone()), &true);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("added")), record);
    }

    /// Archive (deactivate) a record. Requires admin auth.
    pub fn archive(env: Env, record: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Active(record.clone()), &false);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("archived")), record);
    }

    /// VULNERABLE: restores a previously archived record without any auth check.
    ///
    /// Any caller — including an attacker — can reactivate a record that the
    /// admin deliberately archived (e.g. a malicious or deprecated contract).
    ///
    /// # Vulnerability
    /// Missing: `Self::require_admin(&env);`
    pub fn restore(env: Env, record: Address) {
        // ❌ Missing: Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Active(record.clone()), &true);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("restored")), record);
    }

    /// Returns `true` if the record is currently active.
    pub fn is_active(env: Env, record: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Active(record))
            .unwrap_or(false)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableRegistry);
        let admin = Address::generate(&env);
        let record = Address::generate(&env);
        VulnerableRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, record)
    }

    /// Normal flow: admin registers and archives a record.
    #[test]
    fn test_admin_can_archive() {
        let (env, contract_id, _admin, record) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);

        client.register(&record);
        assert!(client.is_active(&record));

        client.archive(&record);
        assert!(!client.is_active(&record));
    }

    /// DEMONSTRATES VULNERABILITY: attacker restores an archived record without auth.
    ///
    /// The admin archives a malicious record; the attacker calls `restore` with
    /// no authorization and the record becomes active again.
    #[test]
    fn test_attacker_can_restore_without_auth() {
        let env = Env::default();
        // Only mock auth for setup calls; the attacker's restore needs NO auth.
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableRegistry);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let record = Address::generate(&env);

        let client = VulnerableRegistryClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.register(&record);
        client.archive(&record);

        // Record is now archived.
        assert!(!client.is_active(&record));

        // Attacker restores it — no auth required by the vulnerable contract.
        // We clear mocked auths to prove no signature is needed.
        env.mock_auths(&[]);
        client.restore(&record);

        // The archived record is active again — unsafe state.
        assert!(
            client.is_active(&record),
            "attacker restored an archived record without authorization"
        );
    }

    /// Boundary: restore on a record that was never registered still sets it active.
    #[test]
    fn test_restore_unregistered_record_sets_active() {
        let (env, contract_id, _admin, record) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);

        // Record was never registered; restore should not be callable by anyone
        // but the vulnerable contract allows it.
        env.mock_auths(&[]);
        client.restore(&record);
        assert!(client.is_active(&record));
    }

    /// Secure version rejects an attacker's restore attempt.
    #[test]
    #[should_panic]
    fn test_secure_rejects_attacker_restore() {
        use crate::secure::SecureRegistryClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureRegistry);
        let admin = Address::generate(&env);
        let record = Address::generate(&env);

        let client = SecureRegistryClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.register(&record);
        client.archive(&record);

        // Clear all mocked auths — attacker has no admin signature.
        env.mock_auths(&[]);
        // This must panic because the secure contract requires admin auth.
        client.restore(&record);
    }
}
