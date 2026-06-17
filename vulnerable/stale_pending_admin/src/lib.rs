//! VULNERABLE: Stale Pending Admin After Cancellation
//!
//! A two-step admin transfer stores a `PendingAdmin` key in persistent storage.
//! When the current admin cancels the transfer, the contract only emits an event
//! but **does not remove** the `PendingAdmin` key from storage.
//!
//! VULNERABILITY: After cancellation the pending address is still present in
//! storage and can call `accept_admin` to seize ownership unexpectedly.
//!
//! SECURE MIRROR: `secure::SecureAdmin` removes the `PendingAdmin` key during
//! cancellation so the proposal is truly invalidated.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    PendingAdmin,
}

#[contract]
pub struct VulnerableAdmin;

#[contractimpl]
impl VulnerableAdmin {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Propose a new admin. Only the current admin may call this.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &new_admin);
        env.events()
            .publish((symbol_short!("proposed"),), (new_admin,));
    }

    /// VULNERABLE: emits a cancellation event but leaves `PendingAdmin` in
    /// storage. The pending address can still call `accept_admin` afterwards.
    ///
    /// # Vulnerability
    /// Missing `env.storage().persistent().remove(&DataKey::PendingAdmin)`.
    /// Impact: a cancelled pending admin can silently accept ownership later.
    pub fn cancel_admin_transfer(env: Env) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        // ❌ BUG: only emits an event — PendingAdmin key is NOT removed.
        env.events()
            .publish((symbol_short!("cancel"),), (current,));
    }

    /// Accept admin ownership. Reads `PendingAdmin` from storage — which is
    /// still present after a buggy cancellation.
    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        pending.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &pending);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::PendingAdmin)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableAdminClient<'static>, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableAdmin);
        let client = VulnerableAdminClient::new(&env, &id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        (env, client, admin)
    }

    /// Demonstrates the vulnerability: after cancellation the pending admin
    /// can still call accept_admin and seize ownership.
    #[test]
    fn test_stale_pending_admin_accepts_after_cancellation() {
        let (env, client, admin) = setup();
        let pending = Address::generate(&env);

        // Step 1: propose a new admin.
        client.propose_admin(&pending);
        assert_eq!(client.get_pending_admin(), Some(pending.clone()));

        // Step 2: current admin cancels the transfer.
        client.cancel_admin_transfer();

        // BUG: pending admin is still in storage after cancellation.
        assert_eq!(
            client.get_pending_admin(),
            Some(pending.clone()),
            "pending admin should have been cleared but was not"
        );

        // Step 3: the stale pending admin accepts — ownership is stolen.
        client.accept_admin();
        assert_eq!(
            client.get_admin(),
            pending,
            "stale pending admin seized ownership after cancellation"
        );
    }

    /// Boundary: without a proposal, accept_admin must panic.
    #[test]
    #[should_panic(expected = "no pending admin")]
    fn test_accept_without_proposal_panics() {
        let (_env, client, _admin) = setup();
        client.accept_admin();
    }

    /// Secure version: propose_admin stores a nonce; accept_admin requires it.
    /// Happy path — correct nonce succeeds.
    #[test]
    fn test_secure_accept_with_correct_nonce_succeeds() {
        use crate::secure::SecureAdminClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAdmin);
        let client = SecureAdminClient::new(&env, &id);
        let admin = Address::generate(&env);
        let pending = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.propose_admin(&pending);

        // First proposal gets nonce = 1.
        client.accept_admin(&1);
        assert_eq!(
            client.get_admin(),
            pending,
            "secure accept with correct nonce must transfer ownership"
        );
    }

    /// Secure version: cancellation removes the pending admin key so
    /// accept_admin panics when called afterwards.
    #[test]
    #[should_panic(expected = "no pending admin")]
    fn test_secure_rejects_stale_accept_after_cancellation() {
        use crate::secure::SecureAdminClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAdmin);
        let client = SecureAdminClient::new(&env, &id);
        let admin = Address::generate(&env);
        let pending = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.propose_admin(&pending);

        // Secure cancel removes the key.
        client.cancel_admin_transfer();
        assert_eq!(
            client.get_pending_admin(),
            None,
            "secure cancel must clear pending admin"
        );

        // This must panic — no pending admin in storage.
        client.accept_admin(&1);
    }

    /// Secure version: wrong nonce must be rejected.
    #[test]
    #[should_panic(expected = "nonce mismatch")]
    fn test_secure_rejects_wrong_nonce() {
        use crate::secure::SecureAdminClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAdmin);
        let client = SecureAdminClient::new(&env, &id);
        let admin = Address::generate(&env);
        let pending = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.propose_admin(&pending);

        // Proposal nonce is 1, but we pass 99.
        client.accept_admin(&99);
    }
}
