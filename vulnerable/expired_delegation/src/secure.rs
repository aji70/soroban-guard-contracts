//! SECURE mirror: enforce delegation expiry before accepting delegate auth.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureAdminContract;

#[contractimpl]
impl SecureAdminContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn delegate_admin(env: Env, delegate: Address, expiry_ledger: u32) {
        Self::require_admin(&env);
        env.storage().persistent().set(&DataKey::Delegate, &delegate);
        env.storage().persistent().set(&DataKey::DelegateExpiry, &expiry_ledger);
    }

    pub fn set_value(env: Env, value: u32) {
        Self::require_admin_or_delegate(&env);
        env.storage().persistent().set(&DataKey::Value, &value);
    }

    pub fn get_value(env: Env) -> u32 {
        env.storage().persistent().get(&DataKey::Value).unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }

    fn require_admin_or_delegate(env: &Env) {
        if let Some(delegate) = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::Delegate)
        {
            // ✅ Enforce expiry before accepting delegate auth.
            let expiry: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::DelegateExpiry)
                .unwrap_or(0);
            assert!(
                env.ledger().sequence() <= expiry,
                "delegation expired"
            );
            delegate.require_auth();
            return;
        }
        Self::require_admin(env);
    }
}
