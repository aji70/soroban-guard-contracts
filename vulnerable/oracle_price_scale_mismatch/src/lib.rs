//! VULNERABLE: Oracle Price Scale Mismatch
//!
//! A lending market that reads prices from two oracles but ignores the
//! `exponent` field each oracle reports alongside its price.  One feed uses
//! a 1e7 scale (exponent = -7) and another uses a 1e9 scale (exponent = -9).
//! Because the contract treats both raw values as if they share the same unit,
//! collateral denominated in the 1e9 feed appears 100× larger than it really
//! is, letting a borrower drain the pool.
//!
//! VULNERABILITY: Oracle price exponent / decimals field is ignored before
//! solvency checks.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Raw price stored by the oracle feed (no exponent applied).
    Price(Symbol),
    /// Exponent reported by the oracle feed (e.g. -7 means value / 1e7).
    Exponent(Symbol),
    /// Collateral deposited by a user (raw token units).
    Collateral(Address),
    /// Debt taken by a user (in normalised USD units, 1e7 scale).
    Debt(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct LendingMarket;

#[contractimpl]
impl LendingMarket {
    /// Register an oracle feed with its raw price and exponent.
    /// `exponent` is the negative power of 10 (e.g. 7 means price / 1e7).
    pub fn set_oracle(env: Env, feed: Symbol, price: i128, exponent: u32) {
        env.storage()
            .persistent()
            .set(&DataKey::Price(feed.clone()), &price);
        env.storage()
            .persistent()
            .set(&DataKey::Exponent(feed), &exponent);
    }

    /// Deposit collateral for `user` denominated in `feed` units.
    pub fn deposit(env: Env, user: Address, feed: Symbol, amount: i128) {
        user.require_auth();
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        // ❌ Raw token units stored without normalising by oracle exponent.
        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Price(feed))
            .unwrap_or(0);
        let collateral_value = amount * price; // BUG: exponent ignored
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user), &(current + collateral_value));
    }

    /// Borrow `amount` (normalised USD, 1e7 scale) against deposited collateral.
    /// VULNERABLE: collateral value was computed without normalising the exponent,
    /// so a 1e9-scale feed inflates collateral 100× vs a 1e7-scale feed.
    pub fn borrow(env: Env, user: Address, amount: i128) -> i128 {
        user.require_auth();
        let collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        let debt: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Debt(user.clone()))
            .unwrap_or(0);
        // ❌ Solvency check uses raw (un-normalised) collateral value.
        assert!(collateral >= debt + amount, "undercollateralised");
        env.storage()
            .persistent()
            .set(&DataKey::Debt(user), &(debt + amount));
        amount
    }

    pub fn get_collateral(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0)
    }

    pub fn get_debt(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Debt(user))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, LendingMarketClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, LendingMarket);
        let client = LendingMarketClient::new(&env, &id);
        let user = Address::generate(&env);
        (env, user, client)
    }

    /// Demonstrates the vulnerability: a 1e9-scale feed inflates collateral
    /// 100× compared to a 1e7-scale feed, allowing overborrowing.
    #[test]
    fn test_vulnerable_overborrow_with_1e9_feed() {
        let (env, user, client) = setup();

        let feed_1e7 = symbol_short!("f7");
        let feed_1e9 = symbol_short!("f9");

        // 1e7 feed: price = 1_000_0000 (= $1.00 at 1e7 scale)
        client.set_oracle(&feed_1e7, &10_000_000_i128, &7);
        // 1e9 feed: price = 1_000_000_000 (= $1.00 at 1e9 scale, but 100× raw)
        client.set_oracle(&feed_1e9, &1_000_000_000_i128, &9);

        // Deposit 1 unit via the 1e9 feed.
        // Correct USD value = 1 * 1_000_000_000 / 1e9 = $1 (at 1e7 scale → 10_000_000)
        // Vulnerable value  = 1 * 1_000_000_000        = 1_000_000_000 (100× inflated)
        client.deposit(&user, &feed_1e9, &1_i128);

        let collateral = client.get_collateral(&user);
        // ❌ Collateral is 100× what it should be.
        assert_eq!(collateral, 1_000_000_000_i128);

        // Attacker borrows 100× more than their real collateral allows.
        let borrowed = client.borrow(&user, &900_000_000_i128);
        assert_eq!(borrowed, 900_000_000_i128);
    }

    /// Boundary: with a correctly-scaled 1e7 feed the same 1-unit deposit
    /// only supports a proportionally smaller borrow.
    #[test]
    fn test_boundary_1e7_feed_correct_scale() {
        let (env, user, client) = setup();
        let feed_1e7 = symbol_short!("f7");
        client.set_oracle(&feed_1e7, &10_000_000_i128, &7);
        client.deposit(&user, &feed_1e7, &1_i128);
        // Collateral = 1 * 10_000_000 = 10_000_000 (correct for 1e7 scale)
        assert_eq!(client.get_collateral(&user), 10_000_000_i128);
        // Can borrow up to 10_000_000, not 1_000_000_000.
        client.borrow(&user, &10_000_000_i128);
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    /// Secure path normalises both feeds to the same scale before solvency check.
    #[test]
    #[should_panic(expected = "undercollateralised")]
    fn test_secure_rejects_overborrow() {
        use crate::secure::SecureLendingClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);
        let user = Address::generate(&env);

        let feed_1e9 = symbol_short!("f9");
        client.set_oracle(&feed_1e9, &1_000_000_000_i128, &9);
        // Deposit 1 unit via 1e9 feed → normalised value = 10_000_000 (1e7 scale)
        client.deposit(&user, &feed_1e9, &1_i128);
        // Attempting to borrow 900_000_000 against 10_000_000 collateral must panic.
        client.borrow(&user, &900_000_000_i128);
    }

    /// Secure path allows a borrow within the normalised collateral limit.
    #[test]
    fn test_secure_allows_valid_borrow() {
        use crate::secure::SecureLendingClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);
        let user = Address::generate(&env);

        let feed_1e9 = symbol_short!("f9");
        client.set_oracle(&feed_1e9, &1_000_000_000_i128, &9);
        client.deposit(&user, &feed_1e9, &1_i128);
        // Normalised collateral = 10_000_000; borrow within limit.
        let borrowed = client.borrow(&user, &5_000_000_i128);
        assert_eq!(borrowed, 5_000_000_i128);
    }
}
