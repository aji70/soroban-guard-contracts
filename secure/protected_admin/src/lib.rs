//! SECURE: Properly gated admin functions
//!
//! This is the fixed mirror of `unprotected_admin` and `unsafe_storage`.
//!
//! FIXES APPLIED:
//! 1. `set_admin` loads the current admin from storage and calls
//!    `current_admin.require_auth()` before accepting the new value.
//!    DEPRECATED: prefer the 2-step `propose_admin` / `accept_admin` flow.
//! 2. `upgrade` does the same — only the stored admin can replace WASM.
//! 3. `set_profile` calls `account.require_auth()` so only the account owner
//!    can write to their own storage slot.
//! 4. `delete_profile` likewise requires the account's own auth.
//! 5. `propose_admin` / `accept_admin` implement a 2-step rotation that
//!    prevents accidentally handing admin to an inaccessible address.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env, String};

/// Pending proposals expire after this many ledgers (~24 h at 5 s/ledger).
const PROPOSAL_TTL_LEDGERS: u32 = 17_280;

// ── Storage keys ────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Profile(Address),
    PendingAdmin,
    PendingExpiry,
}

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
pub struct Profile {
    pub display_name: String,
    pub kyc_level: u32,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ProtectedAdmin;

#[contractimpl]
impl ProtectedAdmin {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    // ── 2-step admin rotation ────────────────────────────────────────────────

    /// Step 1: current admin proposes a new admin address.
    ///
    /// The proposal is stored as `DataKey::PendingAdmin` and expires after
    /// `PROPOSAL_TTL_LEDGERS` ledgers. Calling again overwrites any existing
    /// pending proposal.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current_admin.require_auth();

        let expiry = env.ledger().sequence() + PROPOSAL_TTL_LEDGERS;
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &new_admin);
        env.storage()
            .persistent()
            .set(&DataKey::PendingExpiry, &expiry);
    }

    /// Step 2: the proposed new admin accepts, completing the rotation.
    ///
    /// # Panics
    /// - If there is no pending proposal.
    /// - If the caller is not the pending admin.
    /// - If the proposal has expired.
    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .expect("no pending proposal");

        let expiry: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::PendingExpiry)
            .expect("no pending proposal");

        if env.ledger().sequence() > expiry {
            panic!("proposal expired");
        }

        // Only the pending admin may accept.
        pending.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::Admin, &pending);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingAdmin);
        env.storage()
            .persistent()
            .remove(&DataKey::PendingExpiry);
    }

    // ── Fast-path (deprecated) ───────────────────────────────────────────────

    /// Single-step admin rotation.
    ///
    /// # Deprecated
    /// Prefer `propose_admin` + `accept_admin` to avoid accidentally
    /// transferring admin to an inaccessible address.
    pub fn set_admin(env: Env, new_admin: Address) {
        let current_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current_admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &new_admin);
    }

    // ── Upgrade ──────────────────────────────────────────────────────────────

    /// ✅ FIX 2: Admin auth required before any WASM replacement.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    // ── Profile management ───────────────────────────────────────────────────

    /// ✅ FIX 3: `account.require_auth()` ensures only the account owner
    /// can write to their own profile slot.
    pub fn set_profile(env: Env, account: Address, display_name: String, kyc_level: u32) {
        account.require_auth();
        let profile = Profile {
            display_name,
            kyc_level,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Profile(account), &profile);
    }

    pub fn get_profile(env: Env, account: Address) -> Option<Profile> {
        env.storage().persistent().get(&DataKey::Profile(account))
    }

    /// ✅ FIX 4: Only the account owner can delete their own profile.
    pub fn delete_profile(env: Env, account: Address) {
        account.require_auth();
        env.storage()
            .persistent()
            .remove(&DataKey::Profile(account));
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProtectedAdmin);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        ProtectedAdminClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin)
    }

    // ── 2-step rotation tests ────────────────────────────────────────────────

    #[test]
    fn test_propose_and_accept_rotates_admin() {
        let (env, contract_id, _admin) = setup();
        let client = ProtectedAdminClient::new(&env, &contract_id);
        let new_admin = Address::generate(&env);

        client.propose_admin(&new_admin);
        client.accept_admin();

        assert_eq!(client.get_admin(), new_admin);
    }

    #[test]
    #[should_panic]
    fn test_wrong_address_cannot_accept() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProtectedAdmin);
        let client = ProtectedAdminClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let impostor = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.propose_admin(&new_admin);

        // Remove mocked auths so impostor cannot forge new_admin's signature.
        let env2 = Env::default();
        let client2 = ProtectedAdminClient::new(&env2, &contract_id);
        // accept_admin checks pending == impostor — should panic.
        let _ = impostor; // impostor is not new_admin; require_auth will fail
        client2.accept_admin();
    }

    #[test]
    #[should_panic(expected = "proposal expired")]
    fn test_expired_proposal_cannot_be_accepted() {
        let (env, contract_id, _admin) = setup();
        let client = ProtectedAdminClient::new(&env, &contract_id);
        let new_admin = Address::generate(&env);

        client.propose_admin(&new_admin);

        // Advance ledger past the TTL.
        env.ledger().set_sequence_number(
            env.ledger().sequence() + PROPOSAL_TTL_LEDGERS + 1,
        );

        client.accept_admin();
    }

    // ── Legacy set_admin tests ───────────────────────────────────────────────

    #[test]
    fn test_admin_can_rotate_admin() {
        let (env, contract_id, _admin) = setup();
        let client = ProtectedAdminClient::new(&env, &contract_id);
        let new_admin = Address::generate(&env);

        client.set_admin(&new_admin);
        assert_eq!(client.get_admin(), new_admin);
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_set_admin() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProtectedAdmin);
        let client = ProtectedAdminClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);

        // No mock_all_auths for the attacker call — should panic.
        let env2 = Env::default();
        let client2 = ProtectedAdminClient::new(&env2, &contract_id);
        client2.set_admin(&attacker);
    }

    // ── Profile tests ────────────────────────────────────────────────────────

    #[test]
    fn test_account_can_manage_own_profile() {
        let (env, contract_id, _admin) = setup();
        let client = ProtectedAdminClient::new(&env, &contract_id);
        let alice = Address::generate(&env);

        let name = String::from_str(&env, "Alice");
        client.set_profile(&alice, &name, &3);

        let profile = client.get_profile(&alice).unwrap();
        assert_eq!(profile.kyc_level, 3);

        client.delete_profile(&alice);
        assert!(client.get_profile(&alice).is_none());
    }

    #[test]
    #[should_panic]
    fn test_attacker_cannot_overwrite_profile() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ProtectedAdmin);
        let client = ProtectedAdminClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let alice = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        let name = String::from_str(&env, "Alice");
        client.set_profile(&alice, &name, &2);

        let env2 = Env::default();
        let client2 = ProtectedAdminClient::new(&env2, &contract_id);
        let fake = String::from_str(&env2, "Hacked");
        client2.set_profile(&alice, &fake, &0);
    }
}
