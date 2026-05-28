//! SECURE mirror: verify the feed asset id matches the requested asset before
//! returning the price.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Env, Symbol};

#[contract]
pub struct SecureOracle;

#[contractimpl]
impl SecureOracle {
    pub fn set_feed(env: Env, feed_asset: Symbol, price: i128) {
        env.storage()
            .temporary()
            .set(&DataKey::Feed(feed_asset), &price);
    }

    /// ✅ Panics if `feed_asset` != `requested_asset`.
    pub fn get_price(env: Env, requested_asset: Symbol, feed_asset: Symbol) -> i128 {
        if requested_asset != feed_asset {
            panic!("asset mismatch");
        }
        env.storage()
            .temporary()
            .get(&DataKey::Feed(feed_asset))
            .unwrap_or(0)
    }
}
