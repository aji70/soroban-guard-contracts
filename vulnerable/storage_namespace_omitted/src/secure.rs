//! SECURE mirror: namespaced storage keys prevent module collisions.
//!
//! Fixes the vulnerability in `VulnerableConfig`:
//! - ✅ Uses a typed `DataKey` enum with distinct variants for each module,
//!   so fee config and reward config occupy separate storage slots and can
//!   never overwrite each other.

use soroban_sdk::{contract, contractimpl, contracttype, Env};

/// ✅ Typed enum keys — each variant maps to a unique storage slot.
#[contracttype]
pub enum DataKey {
    /// Storage key for the fee module configuration.
    FeeConfig,
    /// Storage key for the reward module configuration.
    RewardConfig,
}

#[contract]
pub struct SecureConfig;

#[contractimpl]
impl SecureConfig {
    /// Store the fee basis-points value under its own namespaced key.
    pub fn set_fee_config(env: Env, fee_bps: u32) {
        // ✅ Uses DataKey::FeeConfig — distinct from DataKey::RewardConfig.
        env.storage()
            .persistent()
            .set(&DataKey::FeeConfig, &fee_bps);
    }

    pub fn get_fee_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::FeeConfig)
            .unwrap_or(0)
    }

    /// Store the reward rate value under its own namespaced key.
    pub fn set_reward_config(env: Env, reward_rate: u32) {
        // ✅ Uses DataKey::RewardConfig — distinct from DataKey::FeeConfig.
        env.storage()
            .persistent()
            .set(&DataKey::RewardConfig, &reward_rate);
    }

    pub fn get_reward_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardConfig)
            .unwrap_or(0)
    }
}
