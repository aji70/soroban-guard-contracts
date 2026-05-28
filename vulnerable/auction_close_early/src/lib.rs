//! VULNERABLE: Auction Close Before End Ledger
//!
//! The `close` function transfers the NFT to the highest bidder without
//! checking that the auction end ledger has been reached. Any bidder can
//! call `close` immediately after placing the first bid, settling the
//! auction before other participants have a chance to compete.
//!
//! VULNERABILITY: `close` omits the `env.ledger().sequence() >= end_ledger`
//! guard, so early settlement is always possible.
//!
//! SECURE MIRROR: `secure::SecureAuction` requires the current ledger
//! sequence to be at or after `end_ledger` before settlement proceeds.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    HighBidder,
    HighBid,
    EndLedger,
    Closed,
}

#[contract]
pub struct VulnerableAuction;

#[contractimpl]
impl VulnerableAuction {
    /// Initialise the auction with an end ledger and zero bid.
    pub fn initialize(env: Env, end_ledger: u32) {
        if env.storage().persistent().has(&DataKey::EndLedger) {
            panic!("already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::EndLedger, &end_ledger);
        env.storage()
            .persistent()
            .set(&DataKey::HighBid, &0_i128);
        env.storage()
            .persistent()
            .set(&DataKey::Closed, &false);
    }

    /// Place a bid. Must exceed the current high bid.
    pub fn bid(env: Env, bidder: Address, amount: i128) {
        bidder.require_auth();

        let closed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Closed)
            .unwrap_or(false);
        if closed {
            panic!("auction already closed");
        }

        let high_bid: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::HighBid)
            .unwrap_or(0);
        if amount <= high_bid {
            panic!("bid too low");
        }

        env.storage()
            .persistent()
            .set(&DataKey::HighBidder, &bidder);
        env.storage().persistent().set(&DataKey::HighBid, &amount);
    }

    /// VULNERABLE: settles the auction without checking the end ledger.
    ///
    /// # Vulnerability
    /// Missing `env.ledger().sequence() >= end_ledger` check.
    /// Impact: any bidder can close the auction immediately, before
    /// competing bids arrive.
    pub fn close(env: Env) -> Address {
        let closed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Closed)
            .unwrap_or(false);
        if closed {
            panic!("auction already closed");
        }

        // ❌ Missing: end-ledger check
        // let end_ledger: u32 = env.storage().persistent().get(&DataKey::EndLedger).unwrap();
        // if env.ledger().sequence() < end_ledger { panic!("auction not ended"); }

        let winner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::HighBidder)
            .expect("no bids placed");

        env.storage().persistent().set(&DataKey::Closed, &true);
        winner
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

    pub fn is_closed(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Closed)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    fn setup(end_ledger: u32) -> (Env, VulnerableAuctionClient<'static>) {
        let env = Env::default();
        env.ledger().set_sequence_number(100);
        let id = env.register_contract(None, VulnerableAuction);
        let client = VulnerableAuctionClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&end_ledger);
        (env, client)
    }

    /// Vulnerable path: bidder closes before end_ledger and wins immediately.
    #[test]
    fn test_vulnerable_close_before_end_ledger_succeeds() {
        let end_ledger = 500u32;
        let (env, client) = setup(end_ledger);

        let bidder = Address::generate(&env);
        client.bid(&bidder, &100);

        // Current ledger (100) is well before end_ledger (500) — should be rejected
        // but the vulnerable contract allows it.
        let winner = client.close();
        assert_eq!(winner, bidder);
        assert!(client.is_closed());
    }

    /// Boundary: closing exactly at end_ledger should be valid in both versions.
    #[test]
    fn test_close_at_end_ledger_is_valid() {
        let end_ledger = 500u32;
        let (env, client) = setup(end_ledger);

        let bidder = Address::generate(&env);
        client.bid(&bidder, &100);

        env.ledger().set_sequence_number(end_ledger);
        let winner = client.close();
        assert_eq!(winner, bidder);
    }

    /// Secure path: close before end_ledger must panic.
    #[test]
    fn test_secure_rejects_close_before_end_ledger() {
        use crate::secure::SecureAuctionClient;

        let env = Env::default();
        env.ledger().set_sequence_number(100);
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();

        let end_ledger = 500u32;
        client.initialize(&end_ledger);

        let bidder = Address::generate(&env);
        client.bid(&bidder, &100);

        // Attempt to close before end_ledger — must be rejected.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.close();
        }));
        assert!(result.is_err(), "secure close must reject before end ledger");
        assert!(!client.is_closed(), "auction must remain open");
    }

    /// Secure path: close succeeds once end_ledger is reached.
    #[test]
    fn test_secure_close_succeeds_after_end_ledger() {
        use crate::secure::SecureAuctionClient;

        let env = Env::default();
        env.ledger().set_sequence_number(100);
        let id = env.register_contract(None, secure::SecureAuction);
        let client = SecureAuctionClient::new(&env, &id);
        env.mock_all_auths();

        let end_ledger = 500u32;
        client.initialize(&end_ledger);

        let bidder = Address::generate(&env);
        client.bid(&bidder, &100);

        env.ledger().set_sequence_number(end_ledger);
        let winner = client.close();
        assert_eq!(winner, bidder);
        assert!(client.is_closed());
    }
}
