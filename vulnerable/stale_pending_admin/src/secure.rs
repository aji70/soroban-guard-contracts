use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum SecureDataKey {
    Admin,
    PendingAdmin,
    PendingAdminNonce,
    AdminNonce,
}

#[contract]
pub struct SecureAdmin;

#[contractimpl]
impl SecureAdmin {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&SecureDataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&SecureDataKey::Admin, &admin);
        // ✅ Initialise nonce counter to prevent stale acceptance replay.
        env.storage().persistent().set(&SecureDataKey::AdminNonce, &0u32);
    }

    /// Propose a new admin. Increments the transfer nonce and stores it
    /// alongside the pending admin so each proposal creates a unique
    /// acceptance window.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Admin)
            .expect("not initialized");
        current.require_auth();

        let nonce: u32 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::AdminNonce)
            .unwrap_or(0);
        let next_nonce = nonce + 1;
        env.storage()
            .persistent()
            .set(&SecureDataKey::AdminNonce, &next_nonce);

        // ✅ Store the nonce that must be presented by the pending admin.
        env.storage()
            .persistent()
            .set(&SecureDataKey::PendingAdminNonce, &next_nonce);
        env.storage()
            .persistent()
            .set(&SecureDataKey::PendingAdmin, &new_admin);
    }

    /// SECURE: remove the pending admin key on cancellation so the proposal
    /// is truly invalidated.
    pub fn cancel_admin_transfer(env: Env) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        // ✅ Actually remove the pending admin — cancellation is real.
        env.storage().persistent().remove(&SecureDataKey::PendingAdmin);
        env.storage()
            .persistent()
            .remove(&SecureDataKey::PendingAdminNonce);
        env.events().publish((symbol_short!("cancel"),), (current,));
    }

    /// Accept admin ownership. Requires the pending address auth and
    /// a matching nonce that was assigned at proposal time.
    /// The nonce ensures that even if the pending admin key survives
    /// (e.g. from a stale cancellation), a mismatched nonce will block the
    /// acceptance.
    pub fn accept_admin(env: Env, nonce: u32) {
        let pending: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::PendingAdmin)
            .expect("no pending admin");
        pending.require_auth();

        // ✅ Verify the nonce matches the proposal.
        let expected: u32 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::PendingAdminNonce)
            .expect("no pending nonce");
        if nonce != expected {
            panic!("nonce mismatch");
        }

        env.storage().persistent().set(&SecureDataKey::Admin, &pending);
        env.storage()
            .persistent()
            .remove(&SecureDataKey::PendingAdmin);
        env.storage()
            .persistent()
            .remove(&SecureDataKey::PendingAdminNonce);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&SecureDataKey::Admin)
            .expect("not initialized")
    }

    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&SecureDataKey::PendingAdmin)
    }
}
