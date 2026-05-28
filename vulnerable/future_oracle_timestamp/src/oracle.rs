//! Mock Oracle with an explicit `publish_time` field.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum OracleKey {
    Admin,
    Price,
    PublishTime,
}

#[contract]
pub struct MockOracle;

#[contractimpl]
impl MockOracle {
    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&OracleKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&OracleKey::Admin, &admin);
    }

    /// Set price; publish_time = current ledger timestamp.
    pub fn set_price(env: Env, price: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&OracleKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&OracleKey::Price, &price);
        let now = env.ledger().timestamp();
        env.storage()
            .persistent()
            .set(&OracleKey::PublishTime, &now);
    }

    /// Set price with an explicit publish_time (allows future timestamps).
    pub fn set_price_at(env: Env, price: i128, publish_time: u64) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&OracleKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&OracleKey::Price, &price);
        env.storage()
            .persistent()
            .set(&OracleKey::PublishTime, &publish_time);
    }

    pub fn get_price(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&OracleKey::Price)
            .unwrap_or(0)
    }

    pub fn publish_time(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&OracleKey::PublishTime)
            .unwrap_or(0)
    }
}
