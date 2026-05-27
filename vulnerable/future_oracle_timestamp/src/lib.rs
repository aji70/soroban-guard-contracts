//! VULNERABLE: Future Oracle Timestamp
//!
//! A DEX/lending contract reads a price from an oracle that carries a
//! `publish_time` field. The freshness check only verifies that the price is
//! not *too old* (`now - publish_time <= MAX_STALENESS`), but never checks
//! whether `publish_time` is in the future.
//!
//! An attacker who controls the oracle (or can submit a signed price feed) can
//! set `publish_time = now + LARGE_OFFSET`, making the price appear fresh for
//! `LARGE_OFFSET + MAX_STALENESS` seconds — far beyond the intended window.
//!
//! VULNERABILITY: No `publish_time > now` rejection before the staleness check.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod oracle;
pub mod secure;

use oracle::MockOracleClient;

const MAX_STALENESS: u64 = 300; // 5 minutes

#[contracttype]
pub enum DataKey {
    OracleId,
    Collateral(Address),
}

// ── Vulnerable Contract ───────────────────────────────────────────────────────

#[contract]
pub struct VulnerablePricer;

#[contractimpl]
impl VulnerablePricer {
    pub fn init(env: Env, oracle_id: Address) {
        if env.storage().persistent().has(&DataKey::OracleId) {
            panic!("already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::OracleId, &oracle_id);
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Collateral(user);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// ❌ Only checks lower bound (staleness). A future `publish_time` makes
    ///    the price appear fresh for `publish_time - now + MAX_STALENESS` extra
    ///    seconds.
    pub fn get_value(env: Env, user: Address) -> i128 {
        let oracle_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::OracleId)
            .expect("not initialized");
        let oracle = MockOracleClient::new(&env, &oracle_id);
        let price = oracle.get_price();
        let publish_time: u64 = oracle.publish_time();
        let now = env.ledger().timestamp();

        // BUG: `publish_time` may be > `now`; saturating_sub silently treats
        // that as age == 0, so the price always passes the freshness check.
        assert!(
            now.saturating_sub(publish_time) <= MAX_STALENESS,
            "price too stale"
        );

        let collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(user))
            .unwrap_or(0);
        collateral * price
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Env,
    };

    fn setup(env: &Env) -> (oracle::MockOracleClient, VulnerablePricerClient) {
        let oracle_id = env.register_contract(None, oracle::MockOracle);
        let oracle = oracle::MockOracleClient::new(env, &oracle_id);
        let admin = soroban_sdk::Address::generate(env);
        env.mock_all_auths();
        oracle.init(&admin);

        let pricer_id = env.register_contract(None, VulnerablePricer);
        let pricer = VulnerablePricerClient::new(env, &pricer_id);
        pricer.init(&oracle_id);
        (oracle, pricer)
    }

    /// Baseline: a normally-timed price works.
    #[test]
    fn test_normal_price_accepted() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (oracle, pricer) = setup(&env);
        env.mock_all_auths();

        oracle.set_price(&200);
        let user = soroban_sdk::Address::generate(&env);
        pricer.deposit(&user, &10);

        assert_eq!(pricer.get_value(&user), 2000);
    }

    /// VULNERABLE: oracle sets a future publish_time.
    /// At `now = 1000` the price was published at `publish_time = 2000`.
    /// The staleness check computes `1000u64.saturating_sub(2000) == 0 <= 300`,
    /// so the price passes — even though it hasn't happened yet.
    /// Later, at `now = 2300` (= publish_time + MAX_STALENESS), the price is
    /// still accepted, extending the valid window by 1000 extra seconds.
    #[test]
    fn test_future_timestamp_extends_validity_window() {
        let env = Env::default();
        env.ledger().set_timestamp(1000);
        let (oracle, pricer) = setup(&env);
        env.mock_all_auths();

        // Publish a price with a timestamp 1000 s in the future.
        oracle.set_price_at(&200, &2000);

        let user = soroban_sdk::Address::generate(&env);
        pricer.deposit(&user, &10);

        // At now=1000 the price passes (future ts treated as age 0).
        assert_eq!(pricer.get_value(&user), 2000);

        // Advance to now=2300 — still within the inflated window.
        env.ledger().set_timestamp(2300);
        assert_eq!(pricer.get_value(&user), 2000);
        // A correct implementation would have expired this price at now=1300
        // (publish_time=1000 + MAX_STALENESS=300). The future timestamp inflated
        // the valid window by an extra 1000 seconds.
    }

    /// Boundary: price published exactly at MAX_STALENESS seconds ago is still
    /// accepted.
    #[test]
    fn test_boundary_at_max_staleness_accepted() {
        let env = Env::default();
        env.ledger().set_timestamp(300);
        let (oracle, pricer) = setup(&env);
        env.mock_all_auths();

        oracle.set_price(&50); // publish_time = 300
        let user = soroban_sdk::Address::generate(&env);
        pricer.deposit(&user, &4);

        env.ledger().set_timestamp(600); // age == 300 == MAX_STALENESS
        assert_eq!(pricer.get_value(&user), 200);
    }

    /// Boundary: one second past MAX_STALENESS is rejected.
    #[test]
    #[should_panic(expected = "price too stale")]
    fn test_boundary_past_max_staleness_rejected() {
        let env = Env::default();
        env.ledger().set_timestamp(300);
        let (oracle, pricer) = setup(&env);
        env.mock_all_auths();

        oracle.set_price(&50); // publish_time = 300
        let user = soroban_sdk::Address::generate(&env);
        pricer.deposit(&user, &4);

        env.ledger().set_timestamp(601); // age == 301 > MAX_STALENESS
        pricer.get_value(&user);
    }

    // ── secure mirror tests ───────────────────────────────────────────────────

    /// Secure: future publish_time is rejected immediately.
    #[test]
    #[should_panic(expected = "future timestamp")]
    fn test_secure_rejects_future_timestamp() {
        use crate::secure::SecurePricerClient;
        let env = Env::default();
        env.ledger().set_timestamp(1000);

        let oracle_id = env.register_contract(None, oracle::MockOracle);
        let oracle = oracle::MockOracleClient::new(&env, &oracle_id);
        let admin = soroban_sdk::Address::generate(&env);
        env.mock_all_auths();
        oracle.init(&admin);

        let pricer_id = env.register_contract(None, secure::SecurePricer);
        let pricer = SecurePricerClient::new(&env, &pricer_id);
        pricer.init(&oracle_id);

        oracle.set_price_at(&200, &2000); // publish_time in the future
        let user = soroban_sdk::Address::generate(&env);
        pricer.deposit(&user, &10);

        pricer.get_value(&user); // must panic
    }

    /// Secure: normal price still works.
    #[test]
    fn test_secure_accepts_normal_price() {
        use crate::secure::SecurePricerClient;
        let env = Env::default();
        env.ledger().set_timestamp(1000);

        let oracle_id = env.register_contract(None, oracle::MockOracle);
        let oracle = oracle::MockOracleClient::new(&env, &oracle_id);
        let admin = soroban_sdk::Address::generate(&env);
        env.mock_all_auths();
        oracle.init(&admin);

        let pricer_id = env.register_contract(None, secure::SecurePricer);
        let pricer = SecurePricerClient::new(&env, &pricer_id);
        pricer.init(&oracle_id);

        oracle.set_price(&100); // publish_time = 1000
        let user = soroban_sdk::Address::generate(&env);
        pricer.deposit(&user, &5);

        assert_eq!(pricer.get_value(&user), 500);
    }
}
