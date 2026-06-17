//! VULNERABLE: Mixed Collateral Decimals
//!
//! A lending contract that sums collateral from different tokens by adding
//! their raw token units directly.  Token A has 6 decimals and Token B has
//! 18 decimals.  One unit of Token B (1e18 raw) is treated as 1e12× more
//! valuable than one unit of Token A (1e6 raw), even if their USD prices are
//! identical, allowing a borrower to unlock enormous borrowing power with a
//! dust deposit of a high-decimal token.
//!
//! VULNERABILITY: Collateral aggregation adds raw token units across assets
//! without normalising by each token's decimal count and oracle price.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Oracle price for a token symbol (USD, 1e6 scale).
    Price(Symbol),
    /// Decimal count for a token symbol.
    Decimals(Symbol),
    /// Aggregated raw collateral for a user (sum of raw units, NOT normalised).
    Collateral(Address),
    /// Debt taken by a user (USD, 1e6 scale).
    Debt(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct LendingPool;

#[contractimpl]
impl LendingPool {
    /// Register a token with its USD price (1e6 scale) and decimal count.
    pub fn register_token(env: Env, token: Symbol, price_usd: i128, decimals: u32) {
        env.storage()
            .persistent()
            .set(&DataKey::Price(token.clone()), &price_usd);
        env.storage()
            .persistent()
            .set(&DataKey::Decimals(token), &decimals);
    }

    /// Deposit `amount` raw token units of `token` as collateral for `user`.
    /// VULNERABLE: raw units are added directly without decimal normalisation.
    pub fn deposit(env: Env, user: Address, token: Symbol, amount: i128) {
        user.require_auth();
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user.clone()))
            .unwrap_or(0);
        // ❌ Raw units added — a token with 18 decimals inflates value vs 6-decimal token.
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(user), &(current + amount));
    }

    /// Borrow `amount` USD (1e6 scale) against deposited collateral.
    /// VULNERABLE: solvency check compares raw collateral units to USD debt.
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
        // ❌ Raw collateral units compared directly to USD debt amount.
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
    use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, LendingPoolClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, LendingPool);
        let client = LendingPoolClient::new(&env, &id);
        let user = Address::generate(&env);
        (env, user, client)
    }

    /// Demonstrates the vulnerability: depositing 1 raw unit of an 18-decimal
    /// token (worth $1e-18 USD) inflates collateral to 1, which is treated as
    /// 1 USD (1e6 scale) — enabling overborrowing.
    #[test]
    fn test_vulnerable_inflated_borrow_from_high_decimal_token() {
        let (env, user, client) = setup();

        let token_a = symbol_short!("USDC"); // 6 decimals, $1 per token
        let token_b = symbol_short!("WBTC"); // 18 decimals, $1 per token (same price)

        // $1.00 per token at 1e6 USD scale = 1_000_000
        client.register_token(&token_a, &1_000_000_i128, &6);
        client.register_token(&token_b, &1_000_000_i128, &18);

        // Deposit 1 raw unit of the 18-decimal token.
        // Real USD value = 1 / 1e18 * $1 ≈ $0 (negligible).
        // Vulnerable stored collateral = 1 (raw unit).
        client.deposit(&user, &token_b, &1_i128);

        // ❌ Collateral stored as raw 1, which passes the solvency check for
        // a borrow of 1 USD unit — but the real collateral is worth ~$0.
        let collateral = client.get_collateral(&user);
        assert_eq!(collateral, 1_i128);

        // Attacker borrows 1 USD unit backed by essentially zero collateral.
        let borrowed = client.borrow(&user, &1_i128);
        assert_eq!(borrowed, 1_i128);
    }

    /// Boundary: depositing 1 unit of a 6-decimal token ($1) and borrowing
    /// exactly 1_000_000 (= $1 at 1e6 scale) should fail because raw units
    /// (1) < debt (1_000_000) — shows the inconsistency in the vulnerable model.
    #[test]
    #[should_panic(expected = "undercollateralised")]
    fn test_boundary_6_decimal_token_cannot_borrow_usd_amount() {
        let (env, user, client) = setup();
        let token_a = symbol_short!("USDC");
        client.register_token(&token_a, &1_000_000_i128, &6);
        // Deposit 1 raw unit of 6-decimal token (= $0.000001).
        client.deposit(&user, &token_a, &1_i128);
        // Trying to borrow $1 (1_000_000 at 1e6 scale) must fail.
        client.borrow(&user, &1_000_000_i128);
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    /// Secure path normalises collateral to USD (1e6 scale) before storing,
    /// so the 18-decimal dust deposit cannot unlock any meaningful borrow.
    #[test]
    #[should_panic(expected = "undercollateralised")]
    fn test_secure_rejects_dust_deposit_overborrow() {
        use crate::secure::SecurePoolClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecurePool);
        let client = SecurePoolClient::new(&env, &id);
        let user = Address::generate(&env);

        let token_b = symbol_short!("WBTC");
        client.register_token(&token_b, &1_000_000_i128, &18);
        // 1 raw unit of 18-decimal token → normalised USD value rounds to 0.
        client.deposit(&user, &token_b, &1_i128);
        // Must panic: normalised collateral is 0.
        client.borrow(&user, &1_i128);
    }

    /// Secure path: depositing a meaningful amount of a 6-decimal token
    /// correctly computes USD collateral and allows a proportional borrow.
    #[test]
    fn test_secure_allows_valid_borrow_after_normalisation() {
        use crate::secure::SecurePoolClient;
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecurePool);
        let client = SecurePoolClient::new(&env, &id);
        let user = Address::generate(&env);

        let token_a = symbol_short!("USDC");
        // $1 per token, 6 decimals → 1_000_000 raw units = $1.00 (1_000_000 at 1e6)
        client.register_token(&token_a, &1_000_000_i128, &6);
        client.deposit(&user, &token_a, &1_000_000_i128); // deposit $1
                                                          // Borrow $0.50 — within collateral.
        let borrowed = client.borrow(&user, &500_000_i128);
        assert_eq!(borrowed, 500_000_i128);
    }
}
