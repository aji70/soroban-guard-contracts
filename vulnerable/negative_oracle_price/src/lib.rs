//! VULNERABLE: Negative Oracle Price Cast to Positive Collateral Value
//!
//! A lending contract reads a signed price (`i128`) from an oracle and casts
//! it to `u128` before the positivity check.  A negative oracle price wraps
//! via two's-complement into a huge unsigned value, so the collateral
//! calculation returns an astronomically large number instead of panicking.
//!
//! VULNERABILITY: `price as u128` before `> 0` guard — negative prices become
//! huge collateral values, allowing under-collateralised borrows.
//! Severity: Critical
//!
//! Secure mirror: `src/secure.rs` — validate `price > 0` on the signed type
//! first, then use `u128::try_from` for a checked conversion.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Signed oracle price set by the price-feed authority.
    OraclePrice,
    /// Collateral value recorded for an account.
    Collateral(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct LendingContract;

#[contractimpl]
impl LendingContract {
    /// Store a signed oracle price.  In production this would be gated; here
    /// it is open so tests can inject arbitrary (including negative) prices.
    pub fn set_price(env: Env, price: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::OraclePrice, &price);
    }

    /// VULNERABLE: casts the signed oracle price to `u128` *before* checking
    /// that it is positive.  A negative price wraps to a huge unsigned value,
    /// making `collateral_value` enormous and bypassing any borrow limit.
    pub fn deposit_collateral(env: Env, user: Address, amount: u128) -> u128 {
        user.require_auth();
        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::OraclePrice)
            .unwrap_or(0);

        // ❌ Cast before guard — negative price wraps to huge u128.
        let unsigned_price = price as u128;
        assert!(unsigned_price > 0, "price must be positive");

        let collateral_value = amount.saturating_mul(unsigned_price);
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user), &collateral_value);
        collateral_value
    }

    pub fn get_collateral(env: Env, user: Address) -> u128 {
        env.storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, LendingContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, LendingContract);
        let client = LendingContractClient::new(&env, &id);
        let user = Address::generate(&env);
        (env, user, client)
    }

    /// Normal path: positive price produces the expected collateral value.
    #[test]
    fn test_positive_price_works_correctly() {
        let (_env, user, client) = setup();
        client.set_price(&100_i128);
        let collateral = client.deposit_collateral(&user, &10_u128);
        assert_eq!(collateral, 1_000_u128);
    }

    /// VULNERABLE: price = -1 wraps to u128::MAX, so collateral becomes huge.
    /// Demonstrates the flaw: a negative oracle price passes the guard and
    /// produces an astronomically large collateral value.
    #[test]
    fn test_negative_price_wraps_to_huge_collateral() {
        let (_env, user, client) = setup();
        // Inject a negative oracle price (e.g. a buggy or malicious feed).
        client.set_price(&-1_i128);

        // -1_i128 as u128 == u128::MAX — the guard `unsigned_price > 0` passes!
        let collateral = client.deposit_collateral(&user, &1_u128);
        assert_eq!(
            collateral,
            u128::MAX,
            "negative price wrapped to u128::MAX — collateral is astronomically large"
        );
        assert!(
            collateral > 1_000_000_000_u128,
            "attacker has effectively unlimited collateral"
        );
    }

    /// Boundary: price = -1 is the boundary that should be rejected but isn't.
    #[test]
    fn test_boundary_minus_one_is_not_rejected() {
        let (_env, user, client) = setup();
        client.set_price(&-1_i128);
        // This should panic with "price must be positive" but it does NOT —
        // the cast makes -1 look like u128::MAX which is > 0.
        let collateral = client.deposit_collateral(&user, &1_u128);
        // The call succeeds when it should have been rejected.
        assert_ne!(collateral, 0, "boundary -1 was not rejected by the guard");
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    /// Secure path rejects a negative oracle price before any cast.
    #[test]
    #[should_panic(expected = "price must be positive")]
    fn test_secure_rejects_negative_price() {
        use crate::secure::SecureLendingClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);
        let user = Address::generate(&env);
        client.set_price(&-1_i128);
        client.deposit_collateral(&user, &1_u128);
    }

    /// Secure path accepts a valid positive price and computes correctly.
    #[test]
    fn test_secure_accepts_positive_price() {
        use crate::secure::SecureLendingClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);
        let user = Address::generate(&env);
        client.set_price(&100_i128);
        let collateral = client.deposit_collateral(&user, &10_u128);
        assert_eq!(collateral, 1_000_u128);
    }
}
