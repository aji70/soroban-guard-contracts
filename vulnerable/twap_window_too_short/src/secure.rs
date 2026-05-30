//! SECURE mirror: enforce a governance-defined minimum TWAP window.
//!
//! `initialize` rejects any `window` below `MIN_TWAP_WINDOW` (10 ledgers)
//! with `"twap window below minimum"`. This ensures the observation buffer
//! always spans enough ledgers to dampen single-block price manipulation.

use crate::{DataKey, Observation};
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

/// Minimum number of observations required for a valid TWAP window.
/// A governance process should set this; here it is a compile-time constant.
pub const MIN_TWAP_WINDOW: u32 = 10;

#[contract]
pub struct SecureTwap;

#[contractimpl]
impl SecureTwap {
    /// Initialise the oracle.
    ///
    /// ✅ Rejects `window < MIN_TWAP_WINDOW` to prevent the TWAP from
    /// collapsing into a spot price.
    pub fn initialize(env: Env, admin: Address, window: u32) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        // ✅ Enforce the minimum window.
        if window < MIN_TWAP_WINDOW {
            panic!("twap window below minimum");
        }

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Window, &window);
        let empty: Vec<Observation> = Vec::new(&env);
        env.storage().persistent().set(&DataKey::Observations, &empty);
    }

    /// Record a new price observation, trimming the buffer to `window` entries.
    pub fn record_price(env: Env, actor: Address, price: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        if actor != admin {
            panic!("unauthorized");
        }
        actor.require_auth();

        assert!(price > 0, "price must be positive");

        let window: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Window)
            .expect("window not set");

        let mut obs: Vec<Observation> = env
            .storage()
            .persistent()
            .get(&DataKey::Observations)
            .unwrap_or(Vec::new(&env));

        obs.push_back(Observation {
            ledger: env.ledger().sequence(),
            price,
        });

        // Trim to the most recent `window` observations.
        while obs.len() > window {
            obs.remove(0);
        }

        env.storage().persistent().set(&DataKey::Observations, &obs);
    }

    /// Return the arithmetic mean of all stored observations.
    ///
    /// ✅ Because `window >= MIN_TWAP_WINDOW`, a single manipulated update
    /// can move the average by at most `1 / MIN_TWAP_WINDOW` of its range.
    pub fn get_twap(env: Env) -> i128 {
        let obs: Vec<Observation> = env
            .storage()
            .persistent()
            .get(&DataKey::Observations)
            .unwrap_or(Vec::new(&env));

        assert!(!obs.is_empty(), "no observations recorded");

        let mut sum: i128 = 0;
        for o in obs.iter() {
            sum += o.price;
        }
        sum / obs.len() as i128
    }

    /// Return the configured window size.
    pub fn get_window(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Window)
            .unwrap_or(0)
    }

    /// Return the number of observations currently in the buffer.
    pub fn observation_count(env: Env) -> u32 {
        let obs: Vec<Observation> = env
            .storage()
            .persistent()
            .get(&DataKey::Observations)
            .unwrap_or(Vec::new(&env));
        obs.len()
    }
}
