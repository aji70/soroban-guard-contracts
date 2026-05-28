use super::{DataKey, DataKey2};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureAuction;

#[contractimpl]
impl SecureAuction {
    pub fn initialize(env: Env) {
        if env.storage().persistent().has(&DataKey::HighBid) {
            panic!("already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::HighBid, &0_i128);
        env.storage()
            .persistent()
            .set(&DataKey2::RefundBlocked, &false);
    }

    /// Toggle the simulated refund-rejection flag (mirrors the vulnerable contract).
    pub fn set_refund_blocked(env: Env, blocked: bool) {
        env.storage()
            .persistent()
            .set(&DataKey2::RefundBlocked, &blocked);
    }

    /// SECURE: records the new bid first, then credits the previous bidder's
    /// refund to a pull-based claimable balance. A failing "transfer" never
    /// blocks progress because no external call is made during `bid`.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();

        let high_bid: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::HighBid)
            .unwrap_or(0);
        if amount <= high_bid {
            panic!("bid too low");
        }

        // ✅ Credit previous bidder's refund to a claimable balance — no external call.
        if high_bid > 0 {
            if let Some(prev_bidder) = env
                .storage()
                .persistent()
                .get::<DataKey, Address>(&DataKey::HighBidder)
            {
                let existing: i128 = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Refund(prev_bidder.clone()))
                    .unwrap_or(0);
                env.storage()
                    .persistent()
                    .set(&DataKey::Refund(prev_bidder), &(existing + high_bid));
            }
        }

        // ✅ New bid is always recorded regardless of refund state.
        env.storage()
            .persistent()
            .set(&DataKey::HighBidder, &bidder);
        env.storage().persistent().set(&DataKey::HighBid, &amount);
    }

    /// Pull-based: previous bidder claims their own refund when ready.
    pub fn claim_refund(env: Env, bidder: Address) -> i128 {
        bidder.require_auth();
        let key = DataKey::Refund(bidder.clone());
        let amount: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if amount == 0 {
            panic!("no refund available");
        }
        env.storage().persistent().set(&key, &0_i128);
        amount
    }

    pub fn claimable_refund(env: Env, bidder: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Refund(bidder))
            .unwrap_or(0)
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
}
