//! SECURE mirror: validate signed oracle price before casting to unsigned.
//!
//! The positivity check is performed on the original `i128` value.  Only after
//! the check passes is a safe `u128::try_from` conversion attempted, which
//! will panic on any remaining negative value rather than silently wrapping.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureLending;

#[contractimpl]
impl SecureLending {
    /// Store a signed oracle price.
    pub fn set_price(env: Env, price: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::OraclePrice, &price);
    }

    /// ✅ Validates `price > 0` on the signed type before any conversion.
    /// Uses `u128::try_from` for a checked cast — panics if somehow negative.
    pub fn deposit_collateral(env: Env, user: Address, amount: u128) -> u128 {
        user.require_auth();
        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::OraclePrice)
            .unwrap_or(0);

        // ✅ Guard on the signed value — negative prices are caught here.
        assert!(price > 0, "price must be positive");
        // ✅ Checked conversion: belt-and-suspenders against any remaining edge case.
        let unsigned_price = u128::try_from(price).expect("price out of range");

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
