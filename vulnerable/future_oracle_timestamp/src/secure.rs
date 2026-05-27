//! SECURE mirror: reject oracle prices whose `publish_time` is in the future
//! before applying the normal staleness window.
//!
//! Fix: assert `publish_time <= now` first, then check `now - publish_time <= MAX_STALENESS`.

use crate::{oracle::MockOracleClient, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

const MAX_STALENESS: u64 = 300;

#[contract]
pub struct SecurePricer;

#[contractimpl]
impl SecurePricer {
    pub fn init(env: Env, oracle_id: Address) {
        if env.storage().persistent().has(&DataKey::OracleId) {
            panic!("already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::OracleId, &oracle_id);
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Collateral(user);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// ✅ Rejects future publish_time before checking staleness.
    pub fn get_value(env: Env, user: Address) -> i128 {
        let oracle_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::OracleId)
            .expect("not initialized");
        let oracle = MockOracleClient::new(&env, &oracle_id);
        let price = oracle.get_price();
        let publish_time: u64 = oracle.publish_time();
        let now = env.ledger().timestamp();

        // ✅ Guard 1: reject future timestamps.
        assert!(publish_time <= now, "future timestamp");
        // ✅ Guard 2: reject stale prices.
        assert!(now - publish_time <= MAX_STALENESS, "price too stale");

        let collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0);
        collateral * price
    }
}
