use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureAuction;

#[contractimpl]
impl SecureAuction {
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

    /// SECURE: settlement is only allowed once the end ledger has been reached.
    pub fn close(env: Env) -> Address {
        let closed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Closed)
            .unwrap_or(false);
        if closed {
            panic!("auction already closed");
        }

        // ✅ End-ledger guard prevents early settlement.
        let end_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::EndLedger)
            .expect("not initialized");
        if env.ledger().sequence() < end_ledger {
            panic!("auction has not ended yet");
        }

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
