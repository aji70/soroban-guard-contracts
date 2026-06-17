//! VULNERABLE: Assumed Token Decimals
//!
//! A multi-asset contract normalises all token amounts using a hardcoded 7-decimal
//! scale. Tokens with 6 or 9 decimals are over- or under-valued, breaking
//! collateral calculations, swap ratios, and deposit caps.
//!
//! VULNERABILITY: `normalised = amount * 10^7` applied to every token regardless
//! of its actual decimal precision.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

/// Hardcoded assumed decimal precision — the bug.
pub const ASSUMED_DECIMALS: u32 = 7;

#[contracttype]
pub enum DataKey {
    /// Normalised balance per (token, user) pair.
    Balance(Symbol, Address),
    /// Total normalised value deposited per token.
    TotalValue(Symbol),
}

pub(crate) fn normalised_balance(env: &Env, token: &Symbol, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(token.clone(), user.clone()))
        .unwrap_or(0)
}

pub(crate) fn total_value(env: &Env, token: &Symbol) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::TotalValue(token.clone()))
        .unwrap_or(0)
}

/// Normalise `amount` using the hardcoded assumed decimal scale.
pub fn normalise_vulnerable(amount: i128) -> i128 {
    // ❌ BUG: always uses 7 decimals regardless of actual token precision.
    amount * 10_i128.pow(ASSUMED_DECIMALS)
}

#[contract]
pub struct VulnerableMultiAsset;

#[contractimpl]
impl VulnerableMultiAsset {
    /// VULNERABLE: normalises `amount` with a hardcoded 7-decimal scale.
    /// A 6-decimal token is over-valued by 10×; a 9-decimal token is under-valued by 100×.
    pub fn deposit(env: Env, actor: Address, token: Symbol, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        // ❌ BUG: hardcoded decimal assumption.
        let normalised = normalise_vulnerable(amount);

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

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureMultiAssetClient;
    use soroban_sdk::{testutils::Address as _, symbol_short, Address, Env};

    fn setup_vuln(env: &Env) -> VulnerableMultiAssetClient {
        let id = env.register_contract(None, VulnerableMultiAsset);
        VulnerableMultiAssetClient::new(env, &id)
    }

    fn setup_secure(env: &Env) -> SecureMultiAssetClient {
        let id = env.register_contract(None, secure::SecureMultiAsset);
        SecureMultiAssetClient::new(env, &id)
    }

    /// Demonstrates the vulnerability: 1 unit of a 6-decimal token and 1 unit
    /// of a 9-decimal token are both normalised to the same value (10^7),
    /// even though they represent very different real-world amounts.
    #[test]
    fn test_different_decimals_produce_same_normalised_value() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let alice = Address::generate(&env);
        let token6 = symbol_short!("TK6"); // 6-decimal token
        let token9 = symbol_short!("TK9"); // 9-decimal token

        // Deposit 1 raw unit of each token
        client.deposit(&alice, &token6, &1);
        client.deposit(&alice, &token9, &1);

        let val6 = client.balance(&token6, &alice);
        let val9 = client.balance(&token9, &alice);

        // ❌ Both normalise to 10^7 — incorrect for different decimal tokens
        assert_eq!(val6, val9, "vulnerable: both tokens get same normalised value");
        assert_eq!(val6, 10_i128.pow(7));
    }

    /// Boundary: equal human-readable amounts of 6-decimal and 9-decimal tokens
    /// should have different raw amounts (1_000_000 vs 1_000_000_000) but the
    /// vulnerable contract treats them identically after normalisation.
    #[test]
    fn test_equal_human_amounts_differ_in_raw_units() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let alice = Address::generate(&env);
        let token6 = symbol_short!("TK6");
        let token9 = symbol_short!("TK9");

        // 1.0 in 6-decimal = 1_000_000 raw; 1.0 in 9-decimal = 1_000_000_000 raw
        client.deposit(&alice, &token6, &1_000_000);
        client.deposit(&alice, &token9, &1_000_000_000);

        let val6 = client.balance(&token6, &alice);
        let val9 = client.balance(&token9, &alice);

        // ❌ Vulnerable: val9 is 1000× larger than val6 — incorrect accounting
        assert_ne!(val6, val9, "vulnerable: equal human amounts produce unequal normalised values");
    }

    /// Secure: equal human-readable amounts normalise to the same canonical value.
    #[test]
    fn test_secure_equal_human_amounts_normalise_correctly() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_secure(&env);

        let alice = Address::generate(&env);
        let token6 = symbol_short!("TK6");
        let token9 = symbol_short!("TK9");

        // Register tokens with their actual decimals
        client.register_token(&token6, &6u32);
        client.register_token(&token9, &9u32);

        // 1.0 in 6-decimal = 1_000_000 raw; 1.0 in 9-decimal = 1_000_000_000 raw
        client.deposit(&alice, &token6, &1_000_000);
        client.deposit(&alice, &token9, &1_000_000_000);

        let val6 = client.balance(&token6, &alice);
        let val9 = client.balance(&token9, &alice);

        // ✅ Both represent 1.0 human unit → same canonical value
        assert_eq!(val6, val9, "secure: equal human amounts produce equal normalised values");
    }
}
