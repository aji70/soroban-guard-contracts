//! VULNERABLE: Inactive Circuit Breaker
//!
//! A market contract stores a `max_move_bps` threshold (maximum allowed
//! price move in basis points) but the `update_price` function never reads
//! or enforces it. Any price — no matter how extreme — is written directly
//! to storage and immediately consumed by swaps and liquidations.
//!
//! VULNERABILITY: `max_move_bps` is set during initialisation and is readable
//! via `get_config`, but `update_price` ignores it entirely. A manipulated
//! price flows into `swap_out` and `liquidate` without any pause or rejection.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Address authorised to push price updates.
    Admin,
    /// Current market price (scaled by 1e7, i.e. 1.0 == 10_000_000).
    Price,
    /// Maximum allowed single-update move expressed in basis points (1 bps = 0.01 %).
    /// Stored but NEVER checked in the vulnerable implementation.
    MaxMoveBps,
    /// Whether the market is paused (unused in the vulnerable path).
    Paused,
}

// ── Vulnerable market contract ────────────────────────────────────────────────

#[contract]
pub struct VulnerableMarket;

#[contractimpl]
impl VulnerableMarket {
    /// Initialise the market.
    ///
    /// * `initial_price` – starting price (scaled by 1e7).
    /// * `max_move_bps`  – circuit-breaker threshold in basis points.
    ///                     Stored for show; never enforced.
    pub fn initialize(env: Env, admin: Address, initial_price: i128, max_move_bps: u32) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        assert!(initial_price > 0, "price must be positive");
        assert!(max_move_bps > 0, "threshold must be positive");

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Price, &initial_price);
        env.storage().persistent().set(&DataKey::MaxMoveBps, &max_move_bps);
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    /// ❌ BUG: writes the new price without checking `max_move_bps`.
    ///
    /// The circuit-breaker threshold is stored in `DataKey::MaxMoveBps` but
    /// this function never reads it. A price that moves 10 000 % is accepted
    /// just as readily as a 0.01 % move.
    pub fn update_price(env: Env, actor: Address, new_price: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        // Auth check is present — the bug is NOT missing auth, it is the
        // missing threshold check that follows.
        if actor != admin {
            panic!("unauthorized");
        }
        actor.require_auth();

        assert!(new_price > 0, "price must be positive");

        // ❌ Missing: compare new_price against old_price using max_move_bps.
        // The fixture makes this unsafe path reachable and easy to scan.
        let _ = env.storage().persistent().get::<DataKey, u32>(&DataKey::MaxMoveBps); // read but discarded
        env.storage().persistent().set(&DataKey::Price, &new_price);
    }

    /// Simulate a swap that reads the current price.
    ///
    /// Returns the output amount for `amount_in` units at the current price.
    /// Because `update_price` never pauses the market, a manipulated price
    /// flows straight through here.
    pub fn swap_out(env: Env, user: Address, amount_in: i128) -> i128 {
        user.require_auth();
        let paused: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        assert!(!paused, "market paused");

        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Price)
            .expect("price not set");
        // Simple linear pricing: out = amount_in * price / 1e7
        amount_in * price / 10_000_000
    }

    /// Simulate a liquidation that reads the current price.
    ///
    /// Returns the collateral seized for `debt` units at the current price.
    pub fn liquidate(env: Env, liquidator: Address, debt: i128) -> i128 {
        liquidator.require_auth();
        let paused: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        assert!(!paused, "market paused");

        let price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Price)
            .expect("price not set");
        // Collateral seized = debt / price * 1e7 (inverse of swap_out)
        debt * 10_000_000 / price
    }

    /// Return the current price.
    pub fn get_price(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Price)
            .expect("price not set")
    }

    /// Return `(max_move_bps, paused)` — the circuit-breaker config.
    pub fn get_config(env: Env) -> (u32, bool) {
        let max_move_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::MaxMoveBps)
            .unwrap_or(0);
        let paused: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        (max_move_bps, paused)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Initial price: 10_000_000 (== 1.0).
    /// Circuit-breaker threshold: 500 bps (5 %).
    const INITIAL_PRICE: i128 = 10_000_000;
    const MAX_MOVE_BPS: u32 = 500; // 5 %

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableMarket);
        let admin = Address::generate(&env);
        VulnerableMarketClient::new(&env, &contract_id)
            .initialize(&admin, &INITIAL_PRICE, &MAX_MOVE_BPS);
        (env, contract_id, admin)
    }

    // ── Vulnerable path ───────────────────────────────────────────────────────

    /// The circuit-breaker threshold is stored but the contract accepts a price
    /// that is 100× the initial value — a 9 900 % move — without complaint.
    #[test]
    fn test_vulnerable_accepts_extreme_price_move() {
        let (env, contract_id, admin) = setup();
        let client = VulnerableMarketClient::new(&env, &contract_id);

        // Sanity: threshold is stored.
        let (stored_bps, _) = client.get_config();
        assert_eq!(stored_bps, MAX_MOVE_BPS);

        // 9 900 % move — should be rejected by any real circuit breaker.
        let manipulated_price = INITIAL_PRICE * 100;
        client.update_price(&admin, &manipulated_price);

        // ❌ Vulnerable: price was accepted, market is NOT paused.
        assert_eq!(client.get_price(), manipulated_price);
        let (_, paused) = client.get_config();
        assert!(!paused, "market should have paused but did not");
    }

    /// With the manipulated price in place, swap_out returns an inflated amount.
    #[test]
    fn test_vulnerable_swap_uses_manipulated_price() {
        let (env, contract_id, admin) = setup();
        let client = VulnerableMarketClient::new(&env, &contract_id);
        let user = Address::generate(&env);

        // Push a 50× price spike.
        client.update_price(&admin, &(INITIAL_PRICE * 50));

        let out = client.swap_out(&user, &1_000_000);
        // At 50× price: out = 1_000_000 * (10_000_000 * 50) / 10_000_000 = 50_000_000
        assert_eq!(out, 50_000_000);
    }

    /// Boundary: a move exactly at the threshold should be accepted.
    /// In the vulnerable contract this passes trivially (everything passes).
    #[test]
    fn test_vulnerable_boundary_move_accepted() {
        let (env, contract_id, admin) = setup();
        let client = VulnerableMarketClient::new(&env, &contract_id);

        // 5 % move = exactly at the 500 bps threshold.
        let boundary_price = INITIAL_PRICE + (INITIAL_PRICE * 500 / 10_000);
        client.update_price(&admin, &boundary_price);
        assert_eq!(client.get_price(), boundary_price);
    }

    // ── Secure mirror tests ───────────────────────────────────────────────────

    /// Secure contract rejects a price move that exceeds max_move_bps.
    #[test]
    #[should_panic(expected = "price move exceeds circuit breaker threshold")]
    fn test_secure_rejects_extreme_price_move() {
        use crate::secure::SecureMarketClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureMarket);
        let client = SecureMarketClient::new(&env, &id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &INITIAL_PRICE, &MAX_MOVE_BPS);

        // 9 900 % move — must be rejected.
        client.update_price(&admin, &(INITIAL_PRICE * 100));
    }

    /// Secure contract accepts a price move within the threshold.
    #[test]
    fn test_secure_accepts_move_within_threshold() {
        use crate::secure::SecureMarketClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureMarket);
        let client = SecureMarketClient::new(&env, &id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &INITIAL_PRICE, &MAX_MOVE_BPS);

        // 3 % move — within the 5 % threshold.
        let small_move = INITIAL_PRICE + (INITIAL_PRICE * 300 / 10_000);
        client.update_price(&admin, &small_move);
        assert_eq!(client.get_price(), small_move);
    }

    /// Secure contract pauses the market when the threshold is breached,
    /// blocking subsequent swaps.
    #[test]
    #[should_panic(expected = "market paused")]
    fn test_secure_pauses_market_on_breach_blocking_swaps() {
        use crate::secure::SecureMarketClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureMarket);
        let client = SecureMarketClient::new(&env, &id);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        client.initialize(&admin, &INITIAL_PRICE, &MAX_MOVE_BPS);

        // Force a breach via the admin bypass (simulates an oracle pushing a bad price).
        client.force_pause(&admin);

        // swap_out must now panic because the market is paused.
        client.swap_out(&user, &1_000_000);
    }
}
