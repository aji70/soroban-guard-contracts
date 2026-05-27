//! VULNERABLE: Auction Minimum Bid Increment Not Enforced
//!
//! The auction stores a `min_increment` at creation time but the `bid`
//! function only checks `new_bid > current_high_bid`. An attacker can
//! grief the auction by placing bids that are only one unit higher.
//!
//! VULNERABILITY: bid validation uses `amount > high_bid` instead of
//! `amount >= high_bid + min_increment`.
//!
//! SECURE MIRROR: `secure::SecureAuction` enforces the minimum increment.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    HighBidder,
    HighBid,
    MinIncrement,
}

#[contract]
pub struct VulnerableAuction;

#[contractimpl]
impl VulnerableAuction {
    pub fn initialize(env: Env, min_increment: i128) {
        if env.storage().persistent().has(&DataKey::MinIncrement) { panic!("already initialized"); }
        if min_increment <= 0 { panic!("min_increment must be positive"); }
        env.storage().persistent().set(&DataKey::MinIncrement, &min_increment);
        env.storage().persistent().set(&DataKey::HighBid, &0_i128);
    }

    /// VULNERABLE: only checks `amount > high_bid`; ignores `min_increment`.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();
        let high_bid: i128 = env.storage().persistent().get(&DataKey::HighBid).unwrap_or(0);
        // ❌ min_increment is ignored.
        if amount <= high_bid { panic!("bid too low"); }
        env.storage().persistent().set(&DataKey::HighBidder, &bidder);
        env.storage().persistent().set(&DataKey::HighBid, &amount);
    }

    pub fn high_bid(env: Env) -> i128 { env.storage().persistent().get(&DataKey::HighBid).unwrap_or(0) }
    pub fn high_bidder(env: Env) -> Option<Address> { env.storage().persistent().get(&DataKey::HighBidder) }
    pub fn min_increment(env: Env) -> i128 { env.storage().persistent().get(&DataKey::MinIncrement).unwrap_or(0) }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(min_increment: i128) -> (Env, VulnerableAuctionClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableAuction);
        let client = VulnerableAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&min_increment);
        (env, client)
    }

    #[test]
    fn test_vulnerable_accepts_sub_increment_bid() {
        let (env, client) = setup(100);
        let first = Address::generate(&env);
        client.bid(&first, &1000);
        let griefer = Address::generate(&env);
        client.bid(&griefer, &1001); // only +1, well below min_increment=100
        assert_eq!(client.high_bid(), 1001);
    }

    #[test]
    fn test_boundary_exact_increment_accepted_in_vulnerable() {
        let (env, client) = setup(100);
        let bidder = Address::generate(&env);
        client.bid(&bidder, &1000);
        let next = Address::generate(&env);
        client.bid(&next, &1100);
        assert_eq!(client.high_bid(), 1100);
    }

    #[test]
    fn test_secure_rejects_sub_increment_bid() {
        use crate::secure::SecureAuctionClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&100_i128);
        let first = Address::generate(&env);
        client.bid(&first, &1000);
        let griefer = Address::generate(&env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { client.bid(&griefer, &1001); }));
        assert!(result.is_err());
        assert_eq!(client.high_bid(), 1000);
    }

    #[test]
    fn test_secure_accepts_exact_increment_bid() {
        use crate::secure::SecureAuctionClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&100_i128);
        let first = Address::generate(&env);
        client.bid(&first, &1000);
        let next = Address::generate(&env);
        client.bid(&next, &1100);
        assert_eq!(client.high_bid(), 1100);
    }
}
