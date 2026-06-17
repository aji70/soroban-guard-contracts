//! VULNERABLE: Signed-to-Unsigned Wrap
//!
//! A deposit contract that accepts an `i128` amount but casts it to `u128`
//! with `as u128` before the positivity check.  A negative `i128` value
//! reinterprets its two's-complement bit pattern as a huge `u128`, so the
//! `amount > 0` guard (applied after the cast) always passes, and the
//! corrupted value is stored in the balance.
//!
//! VULNERABILITY: Signed input is cast to unsigned before positivity check.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct DepositVault;

#[contractimpl]
impl DepositVault {
    /// VULNERABLE: casts `amount` (i128) to u128 before checking positivity.
    /// A negative i128 becomes a huge u128 via two's-complement reinterpretation,
    /// bypassing the `> 0` guard and storing a corrupted balance.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ❌ Cast happens before the guard — negative values wrap to huge u128.
        let unsigned = amount as u128;
        assert!(unsigned > 0, "amount must be positive");
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &unsigned);
    }

    pub fn get_balance(env: Env, user: Address) -> u128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, DepositVaultClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, DepositVault);
        let client = DepositVaultClient::new(&env, &id);
        let user = Address::generate(&env);
        (env, user, client)
    }

    /// Demonstrates the vulnerability: a negative amount passes the guard and
    /// is stored as a huge u128 value.
    #[test]
    fn test_vulnerable_negative_amount_stored_as_huge_u128() {
        let (env, user, client) = setup();

        // -1_i128 as u128 == u128::MAX (two's-complement wrap).
        client.deposit(&user, &-1_i128);
        let balance = client.get_balance(&user);
        assert_eq!(balance, u128::MAX, "negative i128 wrapped to u128::MAX");
    }

    /// Boundary: i128::MIN as u128 is also a huge positive value (2^127).
    #[test]
    fn test_boundary_i128_min_wraps_to_large_u128() {
        let (env, user, client) = setup();
        client.deposit(&user, &i128::MIN);
        let balance = client.get_balance(&user);
        // i128::MIN as u128 == 2^127
        assert_eq!(balance, i128::MIN as u128);
        assert!(balance > u128::MAX / 2, "wrapped value is enormous");
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    /// Secure path rejects negative amounts before any cast.
    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_secure_rejects_negative_amount() {
        use crate::secure::SecureVaultClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        let user = Address::generate(&env);
        client.deposit(&user, &-1_i128);
    }

    /// Secure path accepts a valid positive amount.
    #[test]
    fn test_secure_accepts_positive_amount() {
        use crate::secure::SecureVaultClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        let user = Address::generate(&env);
        client.deposit(&user, &1_000_i128);
        assert_eq!(client.get_balance(&user), 1_000_u128);
    }
}
