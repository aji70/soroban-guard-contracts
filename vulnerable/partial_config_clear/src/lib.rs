//! VULNERABLE: Partial config update clears omitted fields.
//!
//! A configuration contract that accepts optional update fields but rewrites the
//! full config struct using defaults for omitted values. A caller who updates one
//! field can silently reset fees, caps, or oracle settings.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Config,
}

#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub fee_bps: u32,
    pub max_cap: i128,
    pub oracle: Option<Address>,
}

#[contract]
pub struct PartialConfigClearContract;

#[contractimpl]
impl PartialConfigClearContract {
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

        // BUG: partial update rebuilds the config from defaults for omitted
        // fields, silently clearing values that were previously set.
        let config = Config {
            fee_bps: fee_bps.unwrap_or(0),
            max_cap: max_cap.unwrap_or(0),
            oracle,
        };
        env.storage().persistent().set(&DataKey::Config, &config);
    }

    pub fn get_config(env: Env) -> Config {
        env.storage()
            .persistent()
            .get(&DataKey::Config)
            .expect("config not initialized")
    }
}

pub fn validate_config(config: &Config) {
    assert!(config.fee_bps <= 10_000, "fee too high");
    assert!(config.max_cap > 0, "cap must be positive");
    assert!(config.oracle.is_some(), "oracle is required");
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, PartialConfigClearContractClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, PartialConfigClearContract);
        let client = PartialConfigClearContractClient::new(&env, &id);
        (env, client)
    }

    #[test]
    fn test_vulnerable_partial_update_clears_omitted_fields() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin, &100, &1000, &oracle);
        client.update_config(&admin, &Some(250), &None, &None);

        let config = client.get_config();
        assert_eq!(config.fee_bps, 250);
        assert_eq!(config.max_cap, 0);
        assert_eq!(config.oracle, None);
    }

    #[test]
    fn test_secure_partial_update_preserves_omitted_fields() {
        let env = Env::default();
        let id = env.register_contract(None, PartialConfigClearContract);
        let client = PartialConfigClearContractClient::new(&env, &id);
        let secure_id = env.register_contract(None, secure::SecureContract);
        let secure_client = secure::SecureContractClient::new(&env, &secure_id);

        let admin = Address::generate(&env);
        let oracle = Address::generate(&env);

        env.mock_all_auths();
        secure_client.initialize(&admin, &100, &1000, &oracle);
        secure_client.update_config(&admin, &Some(250), &None, &None);

        let secure_config = secure_client.get_config();
        assert_eq!(secure_config.fee_bps, 250);
        assert_eq!(secure_config.max_cap, 1000);
        assert_eq!(secure_config.oracle, Some(oracle));
    }
}
