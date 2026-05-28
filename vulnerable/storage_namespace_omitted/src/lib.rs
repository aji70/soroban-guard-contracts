//! VULNERABLE: Storage Namespace Omitted
//!
//! Two logical modules — fee configuration and reward configuration — both
//! store their config under the same plain `symbol_short!("Config")` key.
//! Writing one module's config silently overwrites the other's because there
//! is no per-module namespace in the storage key.
//!
//! VULNERABILITY: unrelated modules share the same storage symbol, so
//! `set_reward_config` overwrites the value written by `set_fee_config` and
//! vice-versa.
//!
//! Severity: High

#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

pub mod secure;

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableConfig;

#[contractimpl]
impl VulnerableConfig {
    /// Store the fee basis-points value.
    ///
    /// VULNERABLE: uses the generic key `"Config"` — same as `set_reward_config`.
    pub fn set_fee_config(env: Env, fee_bps: u32) {
        // ❌ Both modules use the same symbol key — writes collide.
        env.storage()
            .persistent()
            .set(&symbol_short!("Config"), &fee_bps);
    }

    /// Read back the fee basis-points value.
    pub fn get_fee_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&symbol_short!("Config"))
            .unwrap_or(0)
    }

    /// Store the reward rate value.
    ///
    /// VULNERABLE: uses the same `"Config"` key as `set_fee_config`, so it
    /// overwrites whatever the fee module stored.
    pub fn set_reward_config(env: Env, reward_rate: u32) {
        // ❌ Same symbol key as set_fee_config — overwrites fee config.
        env.storage()
            .persistent()
            .set(&symbol_short!("Config"), &reward_rate);
    }

    /// Read back the reward rate value.
    pub fn get_reward_config(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&symbol_short!("Config"))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Address, Env};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableConfig);
        (env, contract_id)
    }

    /// Normal: setting fee config stores a value.
    #[test]
    fn test_set_fee_config_stores_value() {
        let (env, contract_id) = setup();
        let client = VulnerableConfigClient::new(&env, &contract_id);
        client.set_fee_config(&100);
        assert_eq!(client.get_fee_config(), 100);
    }

    /// DEMONSTRATES VULNERABILITY: setting reward config after fee config
    /// overwrites the fee value because both share the same storage key.
    #[test]
    fn test_reward_config_overwrites_fee_config() {
        let (env, contract_id) = setup();
        let client = VulnerableConfigClient::new(&env, &contract_id);

        client.set_fee_config(&250);
        assert_eq!(client.get_fee_config(), 250);

        // Writing reward config clobbers the fee config slot.
        client.set_reward_config(&999);

        // Fee config now reads back the reward value — data corruption.
        assert_eq!(
            client.get_fee_config(),
            999,
            "fee config was silently overwritten by reward config"
        );
    }

    /// Boundary: the collision is symmetric — fee config also overwrites reward config.
    #[test]
    fn test_fee_config_overwrites_reward_config() {
        let (env, contract_id) = setup();
        let client = VulnerableConfigClient::new(&env, &contract_id);

        client.set_reward_config(&500);
        client.set_fee_config(&10);

        assert_eq!(
            client.get_reward_config(),
            10,
            "reward config was silently overwritten by fee config"
        );
    }

    /// Secure version stores both values independently under namespaced keys.
    #[test]
    fn test_secure_stores_both_independently() {
        use crate::secure::SecureConfigClient;

        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureConfig);
        let client = SecureConfigClient::new(&env, &contract_id);

        client.set_fee_config(&250);
        client.set_reward_config(&999);

        // Both values are preserved independently.
        assert_eq!(client.get_fee_config(), 250);
        assert_eq!(client.get_reward_config(), 999);
    }
}
