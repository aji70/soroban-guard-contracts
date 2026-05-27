//! VULNERABLE: Auction Minimum Bid Increment Not Enforced
//!
//! The auction stores a `min_increment` at creation time but the `bid`
//! function only checks `new_bid > current_high_bid`. An attacker can
//! grief the auction by placing bids that are only one unit higher,
//! wasting gas for legitimate bidders and stalling price discovery.
//!
//! VULNERABILITY: bid validation uses `amount > high_bid` instead of
//! `amount >= high_bid + min_increment`.
//!
//! SECURE MIRROR: `secure::SecureAuction` enforces the minimum increment
//! and validates that `min_increment > 0` at initialisation.

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
    /// Initialise with a minimum increment (stored but never enforced).
    pub fn initialize(env: Env, min_increment: i128) {
        if env.storage().persistent().has(&DataKey::MinIncrement) {
            panic!("already initialized");
        }
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

    /// VULNERABLE: only checks `amount > high_bid`; ignores `min_increment`.
    ///
    /// # Vulnerability
    /// Missing `amount >= high_bid + min_increment` check.
    /// Impact: griefing bids of +1 unit are accepted, blocking legitimate bidders.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();

        let high_bid: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::HighBid)
            .unwrap_or(0);

        // ❌ Only checks strictly greater — min_increment is ignored.
        if amount <= high_bid {
            panic!("bid too low");
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

    /// Vulnerable path: bid of current_high + 1 is accepted despite min_increment = 100.
    #[test]
    fn test_vulnerable_accepts_sub_increment_bid() {
        let min_increment = 100_i128;
        let (env, client) = setup(min_increment);

        let first_bidder = Address::generate(&env);
        client.bid(&first_bidder, &1000);
        assert_eq!(client.high_bid(), 1000);

        // Grief bid: only +1 above current high, well below min_increment of 100.
        let griefer = Address::generate(&env);
        client.bid(&griefer, &1001);
        assert_eq!(client.high_bid(), 1001);
        assert_eq!(client.high_bidder(), Some(griefer));
    }

    /// Boundary: bid of exactly current_high + min_increment should be the minimum valid bid.
    #[test]
    fn test_boundary_exact_increment_accepted_in_vulnerable() {
        let min_increment = 100_i128;
        let (env, client) = setup(min_increment);

        let bidder = Address::generate(&env);
        client.bid(&bidder, &1000);

        let next_bidder = Address::generate(&env);
        client.bid(&next_bidder, &1100); // exactly +100
        assert_eq!(client.high_bid(), 1100);
    }

    /// Secure path: bid below min_increment must be rejected.
    #[test]
    fn test_secure_rejects_sub_increment_bid() {
        use crate::secure::SecureAuctionClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();

        let min_increment = 100_i128;
        client.initialize(&min_increment);

        let first_bidder = Address::generate(&env);
        client.bid(&first_bidder, &1000);

        // Grief bid: +1 unit — must be rejected.
        let griefer = Address::generate(&env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.bid(&griefer, &1001);
        }));
        assert!(result.is_err(), "secure bid must reject sub-increment amount");
        assert_eq!(client.high_bid(), 1000, "high bid must remain unchanged");
    }

    /// Secure path: bid of exactly current_high + min_increment is accepted.
    #[test]
    fn test_secure_accepts_exact_increment_bid() {
        use crate::secure::SecureAuctionClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();

        client.initialize(&100_i128);

        let first_bidder = Address::generate(&env);
        client.bid(&first_bidder, &1000);

        let next_bidder = Address::generate(&env);
        client.bid(&next_bidder, &1100);
        assert_eq!(client.high_bid(), 1100);
    }
}
