//! SECURE mirror: reject deposits that would mint zero shares.

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

    /// ✅ Panics when integer division would mint zero shares.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let total_assets: i128 = env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(1);
        let total_shares: i128 = env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(1);

        let shares_minted = amount * total_shares / total_assets;
        // ✅ Guard: reject deposits that produce no shares.
        assert!(shares_minted > 0, "deposit mints zero shares");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Shares(user), &(current + shares_minted));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(total_assets + amount));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares + shares_minted));
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
