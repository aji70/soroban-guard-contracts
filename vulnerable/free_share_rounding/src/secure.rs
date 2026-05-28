//! SECURE mirror: use ceiling division so every mint of at least one share
//! always costs at least one asset unit — free-share minting is impossible.

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

    /// ✅ Uses ceiling division so callers always pay at least one asset unit.
    pub fn mint(env: Env, user: Address, shares: i128) {
        user.require_auth();
        assert!(shares > 0, "shares must be positive");

        let total_assets: i128 = env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(1);
        let total_shares: i128 = env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(1);

        // ✅ Ceiling division: always charges at least 1 asset when shares > 0.
        let numerator = shares * total_assets;
        let required_assets = (numerator + total_shares - 1) / total_shares;

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Shares(user), &(current + shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(total_assets + required_assets));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares + shares));
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
