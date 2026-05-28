//! VULNERABLE: Auction Refund Failure Blocks Higher Bids
//!
//! When a new bid arrives, the contract immediately attempts to refund the
//! previous highest bidder inline (push-based). If that refund fails or
//! panics, the entire `bid` transaction reverts, permanently blocking any
//! future bids. A malicious previous bidder can exploit this to freeze the
//! auction at their own bid.
//!
//! VULNERABILITY: `bid` performs an external refund transfer before
//! recording the new bid. A failing refund reverts the whole call.
//!
//! SECURE MIRROR: `secure::SecureAuction` uses pull-based refunds.
//! Outbid amounts are credited to a claimable balance; the new bid is
//! always recorded regardless of whether the previous bidder can receive
//! funds right now.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    HighBidder,
    HighBid,
    /// Pull-based: claimable refund balance for a given address.
    Refund(Address),
}

/// Simulates a refund recipient that rejects incoming transfers.
/// In production this would be a cross-contract call; here we use a flag
/// stored in contract storage to make the failure deterministic in tests.
#[contracttype]
pub enum DataKey2 {
    RefundBlocked,
}

#[contract]
pub struct VulnerableAuction;

#[contractimpl]
impl VulnerableAuction {
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

    /// Toggle the simulated refund-rejection flag.
    /// When `true`, the inline refund in `bid` will panic, blocking all bids.
    pub fn set_refund_blocked(env: Env, blocked: bool) {
        env.storage()
            .persistent()
            .set(&DataKey2::RefundBlocked, &blocked);
    }

    /// VULNERABLE: refunds the previous bidder inline before recording the new bid.
    ///
    /// # Vulnerability
    /// If the simulated refund transfer panics (refund_blocked == true), the
    /// entire transaction reverts and the new bid is never recorded.
    /// Impact: previous bidder can freeze the auction at their own bid.
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

        // ❌ Inline refund before recording new bid.
        // If this fails, the new bid is lost and the auction is frozen.
        if high_bid > 0 {
            let refund_blocked: bool = env
                .storage()
                .persistent()
                .get(&DataKey2::RefundBlocked)
                .unwrap_or(false);
            if refund_blocked {
                panic!("refund transfer failed"); // simulates a rejecting recipient
            }
            // (In a real contract this would be a token transfer to the previous bidder.)
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

    /// Normal path: refund succeeds and new bid is recorded.
    #[test]
    fn test_normal_bid_sequence_works() {
        let (env, client) = setup();

        let first = Address::generate(&env);
        let second = Address::generate(&env);

        client.bid(&first, &100);
        assert_eq!(client.high_bid(), 100);

        client.bid(&second, &200);
        assert_eq!(client.high_bid(), 200);
        assert_eq!(client.high_bidder(), Some(second));
    }

    /// Vulnerable path: previous bidder blocks refund, freezing the auction.
    #[test]
    fn test_vulnerable_refund_block_freezes_auction() {
        let (env, client) = setup();

        let first = Address::generate(&env);
        client.bid(&first, &100);

        // Previous bidder (or attacker) causes refund to fail.
        client.set_refund_blocked(&true);

        let second = Address::generate(&env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.bid(&second, &200);
        }));
        assert!(result.is_err(), "bid must fail when refund is blocked");

        // Auction is frozen: high bid is still the attacker's bid.
        assert_eq!(client.high_bid(), 100, "auction frozen at attacker's bid");
        assert_eq!(client.high_bidder(), Some(first));
    }

    /// Secure path: refund block does not prevent new bids from being recorded.
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

        // Simulate refund rejection — in the secure version this must not matter.
        client.set_refund_blocked(&true);

        let second = Address::generate(&env);
        // Must succeed: new bid is recorded and refund is queued for pull.
        client.bid(&second, &200);

        assert_eq!(client.high_bid(), 200, "new bid must be recorded");
        assert_eq!(client.high_bidder(), Some(second));
        // Previous bidder's refund is available to claim.
        assert_eq!(
            client.claimable_refund(&first),
            100,
            "refund must be claimable"
        );
    }

    /// Secure path: previous bidder can claim their refund independently.
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
