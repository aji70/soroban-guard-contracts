//! SECURE mirror: gate emergency_withdraw behind admin require_auth.
//!
//! Only the stored admin can call emergency_withdraw; all other callers are
//! rejected by the Soroban auth framework.

use crate::{get_balance, set_balance, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureTimeLockVault;

#[contractimpl]
impl SecureTimeLockVault {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn deposit(env: Env, user: Address, amount: i128, unlock_ledger: u32) {
        user.require_auth();
        let new_bal = get_balance(&env, &user) + amount;
        set_balance(&env, &user, new_bal);
        env.storage()
            .persistent()
            .set(&DataKey::UnlockLedger(user), &unlock_ledger);
    }

    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();
        let unlock: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::UnlockLedger(user.clone()))
            .unwrap_or(0);
        if env.ledger().sequence() < unlock {
            panic!("still locked");
        }
        set_balance(&env, &user, 0);
        env.storage()
            .persistent()
            .remove(&DataKey::UnlockLedger(user));
    }

    /// SECURE: only the stored admin may call this.
    pub fn emergency_withdraw(env: Env, user: Address) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized");
        admin.require_auth(); // ✅ enforces admin-only access
        set_balance(&env, &user, 0);
        env.storage()
            .persistent()
            .remove(&DataKey::UnlockLedger(user));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized")
    }
}
