//! SECURE mirror: enforce the circuit-breaker threshold on every price update.
//!
//! `update_price` computes the percentage move between the old and new price
//! in basis points and panics with `"price move exceeds circuit breaker
//! threshold"` when the move exceeds `max_move_bps`. It also sets
//! `DataKey::Paused` to `true` so that `swap_out` and `liquidate` are blocked
//! until an admin explicitly unpauses the market.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureMarket;

#[contractimpl]
impl SecureMarket {
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

    /// ✅ Reads `max_move_bps`, computes the move, and rejects or pauses on breach.
    pub fn update_price(env: Env, actor: Address, new_price: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if actor != admin {
            panic!("unauthorized");
        }
        actor.require_auth();

        assert!(new_price > 0, "price must be positive");

        let old_price: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Price)
            .expect("price not set");

        let max_move_bps: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::MaxMoveBps)
            .expect("threshold not set");

        // Compute absolute move in basis points:
        //   move_bps = |new - old| * 10_000 / old
        let delta = if new_price > old_price {
            new_price - old_price
        } else {
            old_price - new_price
        };
        let move_bps = (delta * 10_000) / old_price;

        if move_bps > max_move_bps as i128 {
            // ✅ Pause the market so swaps and liquidations are blocked.
            env.storage().persistent().set(&DataKey::Paused, &true);
            panic!("price move exceeds circuit breaker threshold");
        }

        env.storage().persistent().set(&DataKey::Price, &new_price);
    }

    /// Swap output at the current price. Blocked when the market is paused.
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
        amount_in * price / 10_000_000
    }

    /// Liquidation at the current price. Blocked when the market is paused.
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
        debt * 10_000_000 / price
    }

    /// Return the current price.
    pub fn get_price(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Price)
            .expect("price not set")
    }

    /// Return `(max_move_bps, paused)`.
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

    /// Admin-only: manually pause the market (e.g. after off-chain detection).
    pub fn force_pause(env: Env, admin: Address) {
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &true);
    }

    /// Admin-only: unpause the market after investigation.
    pub fn unpause(env: Env, admin: Address) {
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if admin != stored_admin {
            panic!("unauthorized");
        }
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &false);
    }
}
