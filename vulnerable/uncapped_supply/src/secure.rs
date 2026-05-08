//! SECURE mirror: track total supply and enforce MAX_SUPPLY cap on mint.

use crate::{DataKey, MAX_SUPPLY};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureTokenContract;

#[contractimpl]
impl SecureTokenContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::TotalSupply, &0i128);
    }

    /// ✅ Fixed: tracks total supply and rejects mints that exceed MAX_SUPPLY.
    pub fn mint(env: Env, to: Address, amount: i128) {
        Self::require_admin(&env);
        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        // ✅ Enforce cap.
        assert!(
            supply + amount <= MAX_SUPPLY,
            "mint would exceed max supply"
        );
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(supply + amount));
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
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
