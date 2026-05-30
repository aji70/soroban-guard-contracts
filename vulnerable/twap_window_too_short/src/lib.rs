//! VULNERABLE: TWAP Window Too Short
//!
//! A time-weighted average price (TWAP) oracle stores a ring-buffer of price
//! observations and averages them over a configurable `window` (number of
//! ledgers to retain). The vulnerability is that `window` is accepted as any
//! positive value — including `1`.
//!
//! When `window == 1` the buffer holds exactly one observation at a time.
//! Every call to `record_price` evicts the previous entry, so `get_twap`
//! always returns the most-recently written price. The TWAP degenerates into
//! a spot price and provides zero manipulation resistance: an attacker can
//! push an extreme price in one ledger and immediately read it back as the
//! "average".
//!
//! VULNERABILITY: `initialize` accepts `window = 1` (or any positive value)
//! without enforcing a governance-defined minimum. `get_twap` then returns a
//! single-sample average that is indistinguishable from a raw spot price.
//!
//! SEVERITY: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

pub mod secure;

// ── Types ─────────────────────────────────────────────────────────────────────

/// A single price observation recorded at a specific ledger sequence number.
#[contracttype]
#[derive(Clone)]
pub struct Observation {
    /// Ledger sequence at which the price was recorded.
    pub ledger: u32,
    /// Price at that ledger (scaled by 1e7; 1.0 == 10_000_000).
    pub price: i128,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Address authorised to push price updates.
    Admin,
    /// Number of observations to retain (the TWAP window size).
    /// Stored but NOT validated against a minimum in the vulnerable path.
    Window,
    /// Ring-buffer of the most recent `window` observations.
    Observations,
}

// ── Vulnerable TWAP oracle ────────────────────────────────────────────────────

#[contract]
pub struct VulnerableTwap;

#[contractimpl]
impl VulnerableTwap {
    /// Initialise the oracle.
    ///
    /// * `window` – number of observations to average. Any positive value is
    ///              accepted, including `1`, which collapses the TWAP to spot.
    pub fn initialize(env: Env, admin: Address, window: u32) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        // ❌ BUG: no minimum window check. window = 1 is silently accepted.
        assert!(window > 0, "window must be positive");

        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Window, &window);
        let empty: Vec<Observation> = Vec::new(&env);
        env.storage().persistent().set(&DataKey::Observations, &empty);
    }

    /// Record a new price observation.
    ///
    /// Appends the current `(ledger, price)` pair to the buffer and trims it
    /// to the last `window` entries. With `window == 1` only the newest entry
    /// survives, making `get_twap` equivalent to `get_price`.
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
        // ❌ With window == 1 this always leaves exactly one entry — spot price.
        while obs.len() > window {
            obs.remove(0);
        }

        env.storage().persistent().set(&DataKey::Observations, &obs);
    }

    /// Return the arithmetic mean of all stored observations.
    ///
    /// ❌ With `window == 1` there is always exactly one observation, so this
    /// returns the last recorded price verbatim — a spot price, not an average.
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn setup_vulnerable(window: u32) -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableTwap);
        let admin = Address::generate(&env);
        VulnerableTwapClient::new(&env, &id).initialize(&admin, &window);
        (env, id, admin)
    }

    fn advance(env: &Env, ledgers: u32) {
        env.ledger().set_sequence_number(env.ledger().sequence() + ledgers);
    }

    // ── Vulnerable path ───────────────────────────────────────────────────────

    /// Window of 1 is accepted — the TWAP degenerates to spot price.
    #[test]
    fn test_vulnerable_window_one_accepted() {
        let (env, id, admin) = setup_vulnerable(1);
        let client = VulnerableTwapClient::new(&env, &id);

        assert_eq!(client.get_window(), 1);

        // Record a normal price.
        client.record_price(&admin, &10_000_000); // 1.0
        assert_eq!(client.observation_count(), 1);
        assert_eq!(client.get_twap(), 10_000_000);
    }

    /// With window == 1, a single manipulated update overwrites the entire
    /// history. The TWAP immediately reflects the manipulated spot price.
    #[test]
    fn test_vulnerable_single_update_overwrites_twap() {
        let (env, id, admin) = setup_vulnerable(1);
        let client = VulnerableTwapClient::new(&env, &id);

        // Establish a baseline price over several ledgers.
        client.record_price(&admin, &10_000_000); // 1.0
        advance(&env, 1);
        client.record_price(&admin, &10_100_000); // 1.01
        advance(&env, 1);
        client.record_price(&admin, &10_050_000); // 1.005

        // Buffer holds only the last entry — history is gone.
        assert_eq!(client.observation_count(), 1);

        // Attacker pushes a 10× spike in one ledger.
        advance(&env, 1);
        client.record_price(&admin, &100_000_000); // 10.0

        // ❌ TWAP == manipulated spot price; no averaging occurred.
        let twap = client.get_twap();
        assert_eq!(twap, 100_000_000,
            "vulnerable: TWAP should equal the manipulated spot price");
    }

    /// Boundary: window == 1 is the exact boundary that should be rejected.
    /// In the vulnerable contract it is silently accepted.
    #[test]
    fn test_vulnerable_boundary_window_one_silently_accepted() {
        // This must NOT panic in the vulnerable implementation.
        let (_env, _id, _admin) = setup_vulnerable(1);
        // If we reach here the boundary was accepted — demonstrating the flaw.
    }

    /// With a larger window the vulnerable contract does average correctly,
    /// confirming the bug is specifically the missing minimum-window guard.
    #[test]
    fn test_vulnerable_larger_window_averages_correctly() {
        let (env, id, admin) = setup_vulnerable(3);
        let client = VulnerableTwapClient::new(&env, &id);

        client.record_price(&admin, &10_000_000);
        advance(&env, 1);
        client.record_price(&admin, &20_000_000);
        advance(&env, 1);
        client.record_price(&admin, &30_000_000);

        // Average of 10M, 20M, 30M = 20M.
        assert_eq!(client.get_twap(), 20_000_000);

        // A spike now only moves the average by 1/3.
        advance(&env, 1);
        client.record_price(&admin, &100_000_000);
        // Buffer: [20M, 30M, 100M] → avg = 50M — still dampened.
        let twap = client.get_twap();
        assert!(twap < 100_000_000,
            "larger window dampens the spike: twap={}", twap);
    }

    // ── Secure mirror tests ───────────────────────────────────────────────────

    /// Secure contract rejects window == 1 at initialisation.
    #[test]
    #[should_panic(expected = "twap window below minimum")]
    fn test_secure_rejects_window_one() {
        use crate::secure::SecureTwapClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTwap);
        let client = SecureTwapClient::new(&env, &id);
        let admin = Address::generate(&env);

        // window = 1 must be rejected.
        client.initialize(&admin, &1);
    }

    /// Secure contract rejects any window below MIN_TWAP_WINDOW.
    #[test]
    #[should_panic(expected = "twap window below minimum")]
    fn test_secure_rejects_window_below_minimum() {
        use crate::secure::SecureTwapClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTwap);
        let client = SecureTwapClient::new(&env, &id);
        let admin = Address::generate(&env);

        // MIN_TWAP_WINDOW is 10; window = 9 must also be rejected.
        client.initialize(&admin, &9);
    }

    /// Secure contract accepts a window at or above the minimum.
    #[test]
    fn test_secure_accepts_window_at_minimum() {
        use crate::secure::SecureTwapClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTwap);
        let client = SecureTwapClient::new(&env, &id);
        let admin = Address::generate(&env);

        // Exactly at the minimum — must succeed.
        client.initialize(&admin, &10);
        assert_eq!(client.get_window(), 10);
    }

    /// With a secure window, a single manipulated update cannot dominate the TWAP.
    #[test]
    fn test_secure_single_spike_dampened_by_window() {
        use crate::secure::SecureTwapClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTwap);
        let client = SecureTwapClient::new(&env, &id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &10);

        // Fill the window with a stable price of 10_000_000.
        for i in 0..10_u32 {
            env.ledger().set_sequence_number(i);
            client.record_price(&admin, &10_000_000);
        }

        // One spike at 10× the normal price.
        env.ledger().set_sequence_number(10);
        client.record_price(&admin, &100_000_000);

        // TWAP = (9 * 10_000_000 + 100_000_000) / 10 = 19_000_000
        // Still far below the manipulated spot price of 100_000_000.
        let twap = client.get_twap();
        assert!(twap < 100_000_000,
            "secure: spike must not dominate TWAP; got {}", twap);
        assert_eq!(twap, 19_000_000);
    }
}
