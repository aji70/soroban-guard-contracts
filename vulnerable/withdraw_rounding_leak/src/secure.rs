//! SECURE mirror: round shares_to_burn up (ceiling division) and reject zero-burn withdrawals.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn initialize(env: Env, seed_assets: i128, seed_shares: i128) {
        assert!(seed_assets > 0 && seed_shares > 0, "seed must be positive");
        if env.storage().persistent().has(&DataKey::TotalAssets) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::TotalAssets, &seed_assets);
        env.storage().persistent().set(&DataKey::TotalShares, &seed_shares);
    }

    pub fn seed_shares(env: Env, user: Address, shares: i128) {
        env.storage().persistent().set(&DataKey::Shares(user), &shares);
    }

    /// ✅ Ceiling division: `(a + b - 1) / b` rounds shares_to_burn up.
    pub fn withdraw(env: Env, user: Address, assets: i128) {
        user.require_auth();
        assert!(assets > 0, "assets must be positive");

        let total_assets: i128 = env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(1);
        let total_shares: i128 = env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(1);

        // ✅ Ceiling division — withdrawer cannot pay fewer shares than proportional.
        let shares_to_burn = (assets * total_shares + total_assets - 1) / total_assets;
        assert!(shares_to_burn > 0, "withdrawal burns zero shares");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        assert!(current >= shares_to_burn, "insufficient shares");

        env.storage()
            .persistent()
            .set(&DataKey::Shares(user), &(current - shares_to_burn));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(total_assets - assets));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares - shares_to_burn));
    }

    pub fn shares_of(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Shares(user))
            .unwrap_or(0)
    }

    pub fn total_shares(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(0)
    }

    pub fn total_assets(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(0)
    }
}
