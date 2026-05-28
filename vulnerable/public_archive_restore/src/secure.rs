//! SECURE mirror: archive/restore lifecycle with admin authorization.
//!
//! Fixes the vulnerability in `VulnerableRegistry`:
//! - ✅ `restore` requires admin authorization before reactivating a record.
//! - ✅ Lifecycle events are emitted for both archive and restore operations.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureRegistry;

#[contractimpl]
impl SecureRegistry {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn register(env: Env, record: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Active(record.clone()), &true);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("added")), record);
    }

    pub fn archive(env: Env, record: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Active(record.clone()), &false);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("archived")), record);
    }

    /// ✅ Requires admin authorization before restoring an archived record.
    pub fn restore(env: Env, record: Address) {
        // ✅ Admin must sign this transaction.
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Active(record.clone()), &true);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("restored")), record);
    }

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

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}
