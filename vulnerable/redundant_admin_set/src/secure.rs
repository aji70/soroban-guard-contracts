//! SECURE: rejects a no-op admin rotation.
use crate::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureAdminContract;

#[contractimpl]
impl SecureAdminContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// SECURE: rejects setting the admin to the address that is already admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        let current: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        current.require_auth();

        // ✅ Reject a no-op rotation.
        if new_admin == current {
            panic!("new_admin is already admin");
        }

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events()
            .publish((symbol_short!("AdmChng"),), (current, new_admin));
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}
