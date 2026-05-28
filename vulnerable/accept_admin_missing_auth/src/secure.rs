use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum SecureDataKey {
    Admin,
    PendingAdmin,
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
    }

    /// Propose a new admin. Only the current admin may call this.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        env.storage()
            .persistent()
            .set(&SecureDataKey::PendingAdmin, &new_admin);
        env.events()
            .publish((symbol_short!("proposed"),), (new_admin,));
    }

    /// Cancel a pending transfer. Only the current admin may call this.
    pub fn cancel_admin_transfer(env: Env) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        env.storage().persistent().remove(&SecureDataKey::PendingAdmin);
        env.events()
            .publish((symbol_short!("cancel"),), (current,));
    }

    /// SECURE: require the pending admin to authorise the transfer before
    /// promoting them.
    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::PendingAdmin)
            .expect("no pending admin");
        // ✅ Require the pending admin to sign the acceptance.
        pending.require_auth();
        env.storage().persistent().set(&SecureDataKey::Admin, &pending);
        env.storage()
            .persistent()
            .remove(&SecureDataKey::PendingAdmin);
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
