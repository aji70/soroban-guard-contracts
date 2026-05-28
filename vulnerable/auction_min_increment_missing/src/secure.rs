use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureAuction;

#[contractimpl]
impl SecureAuction {
    /// Initialise with a validated minimum increment.
    pub fn initialize(env: Env, min_increment: i128) {
        if env.storage().persistent().has(&DataKey::MinIncrement) {
            panic!("already initialized");
        }
        // ✅ Validate increment is meaningful at creation time.
        if min_increment <= 0 {
            panic!("min_increment must be positive");
        }
        env.storage()
            .persistent()
            .set(&DataKey::MinIncrement, &min_increment);
        env.storage()
            .persistent()
            .set(&DataKey::HighBid, &0_i128);
    }

    /// SECURE: requires `amount >= high_bid + min_increment`.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();

        let high_bid: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::HighBid)
            .unwrap_or(0);
        let min_increment: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::MinIncrement)
            .expect("not initialized");

        // ✅ Enforce minimum increment — grief bids are rejected.
        let required = high_bid
            .checked_add(min_increment)
            .expect("overflow in bid threshold");
        if amount < required {
            panic!("bid does not meet minimum increment");
        }

        env.storage()
            .persistent()
            .set(&DataKey::HighBidder, &bidder);
        env.storage().persistent().set(&DataKey::HighBid, &amount);
    }

    pub fn high_bid(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::HighBid)
            .unwrap_or(0)
    }

    pub fn high_bidder(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::HighBidder)
    }

    pub fn min_increment(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::MinIncrement)
            .unwrap_or(0)
    }
}
