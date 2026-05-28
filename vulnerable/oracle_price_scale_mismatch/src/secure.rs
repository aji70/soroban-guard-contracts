//! SECURE mirror: normalise oracle price by its exponent before solvency checks.
//!
//! Every price is scaled to a common 1e7 base before being stored as collateral
//! value, so feeds with different exponents cannot inflate borrowing power.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct SecureLending;

/// Scale `price` (raw oracle value) down to a 1e7 base using `exponent`.
/// `exponent` is the negative power of 10 the oracle uses (e.g. 9 → divide by 1e9,
/// then multiply by 1e7 → net divide by 100).
fn normalise(price: i128, exponent: u32) -> i128 {
    // Target scale is 1e7.  If exponent > 7 we divide; if < 7 we multiply.
    if exponent >= 7 {
        let divisor = 10_i128.pow(exponent - 7);
        price / divisor
    } else {
        let multiplier = 10_i128.pow(7 - exponent);
        price * multiplier
    }
}

#[contractimpl]
impl SecureLending {
    pub fn set_oracle(env: Env, feed: Symbol, price: i128, exponent: u32) {
        env.storage().persistent().set(&DataKey::Price(feed.clone()), &price);
        env.storage().persistent().set(&DataKey::Exponent(feed), &exponent);
    }

    pub fn deposit(env: Env, user: Address, feed: Symbol, amount: i128) {
        user.require_auth();
        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Price(feed.clone()))
            .unwrap_or(0);
        let exponent: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Exponent(feed))
            .unwrap_or(7);
        // ✅ Normalise to 1e7 scale before computing collateral value.
        let unit_value = normalise(price, exponent);
        let collateral_value = amount * unit_value;
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user), &(current + collateral_value));
    }

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
        // ✅ Solvency check uses normalised collateral value.
        assert!(collateral >= debt + amount, "undercollateralised");
        env.storage()
            .persistent()
            .set(&DataKey::Debt(user), &(debt + amount));
        amount
    }
}
