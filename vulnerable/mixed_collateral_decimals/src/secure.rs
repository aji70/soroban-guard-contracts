//! SECURE mirror: normalise collateral to USD (1e6 scale) using token decimals
//! and oracle price before summing across assets.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct SecurePool;

/// Convert `raw_amount` token units to USD at 1e6 scale.
/// `price_usd` is the token price in USD at 1e6 scale (e.g. 1_000_000 = $1).
/// `decimals` is the token's decimal count.
fn to_usd(raw_amount: i128, price_usd: i128, decimals: u32) -> i128 {
    // USD value = raw_amount * price_usd / 10^decimals
    // We keep 1e6 scale: divide by 10^decimals, multiply by price_usd already at 1e6.
    let divisor = 10_i128.pow(decimals);
    raw_amount * price_usd / divisor
}

#[contractimpl]
impl SecurePool {
    pub fn register_token(env: Env, token: Symbol, price_usd: i128, decimals: u32) {
        env.storage()
            .persistent()
            .set(&DataKey::Price(token.clone()), &price_usd);
        env.storage()
            .persistent()
            .set(&DataKey::Decimals(token), &decimals);
    }

    pub fn deposit(env: Env, user: Address, token: Symbol, amount: i128) {
        user.require_auth();
        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Price(token.clone()))
            .unwrap_or(0);
        let decimals: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Decimals(token))
            .unwrap_or(0);
        // ✅ Normalise to USD (1e6 scale) before adding to collateral.
        let usd_value = to_usd(amount, price, decimals);
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user), &(current + usd_value));
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
        // ✅ Both collateral and debt are in USD (1e6 scale) — apples-to-apples.
        assert!(collateral >= debt + amount, "undercollateralised");
        env.storage()
            .persistent()
            .set(&DataKey::Debt(user), &(debt + amount));
        amount
    }
}
