//! SECURE: Merge partial configuration updates.
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{validate_config, Config, DataKey};

#[contract]
pub struct SecureContract;

#[contractimpl]
impl SecureContract {
    pub fn initialize(env: Env, admin: Address, fee_bps: u32, max_cap: i128, oracle: Address) {
        admin.require_auth();
        let config = Config {
            fee_bps,
            max_cap,
            oracle: Some(oracle),
        };
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Config, &config);
    }

    pub fn update_config(
        env: Env,
        actor: Address,
        fee_bps: Option<u32>,
        max_cap: Option<i128>,
        oracle: Option<Address>,
    ) {
        actor.require_auth();
        let mut config: Config = env
            .storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not initialized");

        if let Some(fee) = fee_bps {
            config.fee_bps = fee;
        }
        if let Some(cap) = max_cap {
            config.max_cap = cap;
        }
        if let Some(oracle) = oracle {
            config.oracle = Some(oracle);
        }

        validate_config(&config);
        env.storage().persistent().set(&DataKey::Config, &config);
    }

    pub fn get_config(env: Env) -> Config {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not initialized")
    }
}
