#![no_std]
use super::{normalised_balance, total_value, DataKey};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

/// Canonical scale: all amounts normalised to 9 decimals internally.
const CANONICAL_DECIMALS: u32 = 9;

#[contracttype]
pub enum SecureDataKey {
    TokenDecimals(Symbol),
}

fn token_decimals(env: &Env, token: &Symbol) -> u32 {
    env.storage()
        .persistent()
        .get(&SecureDataKey::TokenDecimals(token.clone()))
        .expect("token not registered")
}

/// Normalise `amount` from `token_decimals` to `CANONICAL_DECIMALS`.
fn normalise(amount: i128, decimals: u32) -> i128 {
    if decimals <= CANONICAL_DECIMALS {
        amount * 10_i128.pow(CANONICAL_DECIMALS - decimals)
    } else {
        amount / 10_i128.pow(decimals - CANONICAL_DECIMALS)
    }
}

#[contract]
pub struct SecureMultiAsset;

#[contractimpl]
impl SecureMultiAsset {
    /// Register a token with its actual decimal precision.
    pub fn register_token(env: Env, token: Symbol, decimals: u32) {
        env.storage()
            .persistent()
            .set(&SecureDataKey::TokenDecimals(token), &decimals);
    }

    /// SECURE: normalises using the per-token registered decimal count.
    pub fn deposit(env: Env, actor: Address, token: Symbol, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        // ✅ Per-token decimal lookup — no hardcoded assumption.
        let decimals = token_decimals(&env, &token);
        let normalised = normalise(amount, decimals);
        assert!(normalised > 0, "normalised amount is zero");

        let prev = normalised_balance(&env, &token, &actor);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(token.clone(), actor), &(prev + normalised));

        let tv = total_value(&env, &token);
        env.storage()
            .persistent()
            .set(&DataKey::TotalValue(token), &(tv + normalised));
    }

    pub fn balance(env: Env, token: Symbol, user: Address) -> i128 {
        normalised_balance(&env, &token, &user)
    }

    pub fn total_value(env: Env, token: Symbol) -> i128 {
        total_value(&env, &token)
    }
}
