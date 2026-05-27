//! VULNERABLE: Auction Refund Failure Blocks Higher Bids
//!
//! When a new bid arrives, the contract immediately attempts to refund the
//! previous highest bidder inline (push-based). If that refund fails, the
//! entire `bid` transaction reverts, permanently blocking future bids.
//!
//! VULNERABILITY: `bid` performs an external refund before recording the
//! new bid. A failing refund reverts the whole call.
//!
//! SECURE MIRROR: `secure::SecureAuction` uses pull-based refunds.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    HighBidder,
    HighBid,
    Refund(Address),
}

#[contracttype]
pub enum DataKey2 {
    RefundBlocked,
}

#[contract]
pub struct VulnerableAuction;

#[contractimpl]
impl VulnerableAuction {
    pub fn initialize(env: Env) {
        if env.storage().persistent().has(&DataKey::HighBid) { panic!("already initialized"); }
        env.storage().persistent().set(&DataKey::HighBid, &0_i128);
        env.storage().persistent().set(&DataKey2::RefundBlocked, &false);
    }

    pub fn set_refund_blocked(env: Env, blocked: bool) {
        env.storage().persistent().set(&DataKey2::RefundBlocked, &blocked);
    }

    /// VULNERABLE: inline refund before recording new bid.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();
        let high_bid: i128 = env.storage().persistent().get(&DataKey::HighBid).unwrap_or(0);
        if amount <= high_bid { panic!("bid too low"); }
        // ❌ Inline refund — if this panics, new bid is never recorded.
        if high_bid > 0 {
            let blocked: bool = env.storage().persistent().get(&DataKey2::RefundBlocked).unwrap_or(false);
            if blocked { panic!("refund transfer failed"); }
        }
        env.storage().persistent().set(&DataKey::HighBidder, &bidder);
        env.storage().persistent().set(&DataKey::HighBid, &amount);
    }

    pub fn high_bid(env: Env) -> i128 { env.storage().persistent().get(&DataKey::HighBid).unwrap_or(0) }
    pub fn high_bidder(env: Env) -> Option<Address> { env.storage().persistent().get(&DataKey::HighBidder) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableAuctionClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableAuction);
        let client = VulnerableAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();
        (env, client)
    }

    #[test]
    fn test_normal_bid_sequence_works() {
        let (env, client) = setup();
        let first = Address::generate(&env);
        let second = Address::generate(&env);
        client.bid(&first, &100);
        client.bid(&second, &200);
        assert_eq!(client.high_bid(), 200);
    }

    #[test]
    fn test_vulnerable_refund_block_freezes_auction() {
        let (env, client) = setup();
        let first = Address::generate(&env);
        client.bid(&first, &100);
        client.set_refund_blocked(&true);
        let second = Address::generate(&env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { client.bid(&second, &200); }));
        assert!(result.is_err());
        assert_eq!(client.high_bid(), 100);
        assert_eq!(client.high_bidder(), Some(first));
    }

    #[test]
    fn test_secure_bid_succeeds_despite_refund_block() {
        use crate::secure::SecureAuctionClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();
        let first = Address::generate(&env);
        client.bid(&first, &100);
        client.set_refund_blocked(&true);
        let second = Address::generate(&env);
        client.bid(&second, &200);
        assert_eq!(client.high_bid(), 200);
        assert_eq!(client.claimable_refund(&first), 100);
    }

    #[test]
    fn test_secure_previous_bidder_can_claim_refund() {
        use crate::secure::SecureAuctionClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();
        let first = Address::generate(&env);
        client.bid(&first, &100);
        let second = Address::generate(&env);
        client.bid(&second, &200);
        assert_eq!(client.claimable_refund(&first), 100);
        let claimed = client.claim_refund(&first);
        assert_eq!(claimed, 100);
        assert_eq!(client.claimable_refund(&first), 0);
    }
}
