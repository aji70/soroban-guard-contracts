//! VULNERABLE: Absolute-Value Overflow on i128::MIN
//!
//! A risk module that computes the absolute debt delta with `i128::abs()`.
//! `i128::MIN.abs()` cannot be represented as a positive `i128` — in debug
//! builds Rust panics; in release builds with `overflow-checks = true` it also
//! panics.  Without that flag the result silently wraps back to `i128::MIN`,
//! a large negative number that corrupts any downstream solvency check.
//!
//! VULNERABILITY: `i128::MIN` passed through an unchecked `abs()` call.
//!
//! SEVERITY: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    DebtDelta(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct RiskModule;

#[contractimpl]
impl RiskModule {
    /// VULNERABLE: stores `abs(delta)` without guarding against `i128::MIN`.
    /// `i128::MIN.abs()` overflows — panics with overflow-checks or wraps to
    /// `i128::MIN` without them, storing a negative "absolute" value.
    pub fn record_delta(env: Env, user: Address, delta: i128) {
        user.require_auth();
        // ❌ Unchecked abs — panics or wraps on i128::MIN.
        let abs_delta = delta.abs();
        env.storage()
            .persistent()
            .set(&DataKey::DebtDelta(user), &abs_delta);
    }

    pub fn get_delta(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::DebtDelta(user))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, RiskModuleClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, RiskModule);
        let client = RiskModuleClient::new(&env, &id);
        let user = Address::generate(&env);
        (env, user, client)
    }

    /// Normal negative delta: abs() works correctly for values other than MIN.
    #[test]
    fn test_normal_negative_delta_abs_correct() {
        let (env, user, client) = setup();
        client.record_delta(&user, &-42_i128);
        assert_eq!(client.get_delta(&user), 42_i128);
    }

    /// Demonstrates the vulnerability: i128::MIN.abs() panics (overflow-checks on)
    /// or wraps to i128::MIN (overflow-checks off), corrupting the stored delta.
    #[test]
    #[should_panic]
    fn test_vulnerable_i128_min_panics_or_wraps() {
        let (env, user, client) = setup();
        // ❌ i128::MIN has no positive representation in i128 — this overflows.
        client.record_delta(&user, &i128::MIN);
    }

    /// Boundary: i128::MIN + 1 is the most-negative value abs() can handle.
    #[test]
    fn test_boundary_i128_min_plus_one_is_safe() {
        let (env, user, client) = setup();
        client.record_delta(&user, &(i128::MIN + 1));
        assert_eq!(client.get_delta(&user), i128::MAX);
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    /// Secure path rejects i128::MIN before calling abs().
    #[test]
    #[should_panic(expected = "delta out of range")]
    fn test_secure_rejects_i128_min() {
        use crate::secure::SecureRiskClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureRisk);
        let client = SecureRiskClient::new(&env, &id);
        let user = Address::generate(&env);
        client.record_delta(&user, &i128::MIN);
    }

    /// Secure path correctly handles a normal negative delta.
    #[test]
    fn test_secure_normal_delta_stored_correctly() {
        use crate::secure::SecureRiskClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureRisk);
        let client = SecureRiskClient::new(&env, &id);
        let user = Address::generate(&env);
        client.record_delta(&user, &-100_i128);
        assert_eq!(client.get_delta(&user), 100_i128);
    }
}
