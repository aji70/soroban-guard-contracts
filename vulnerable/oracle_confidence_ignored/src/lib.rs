//! VULNERABLE: Oracle Confidence Interval Ignored
//!
//! The oracle returns a price together with a confidence interval that
//! expresses how uncertain the price feed is at that moment.  A wide
//! confidence interval (e.g. confidence > 5 % of price) means the reported
//! price could be significantly wrong — yet this contract discards that
//! metadata entirely and acts on the raw price as if it were reliable.
//!
//! VULNERABILITY: `consume_price` reads `price` and `timestamp` from the
//! oracle response but silently drops `confidence`.  A low-quality price
//! (e.g. during a market disruption or thin-liquidity window) can therefore
//! trigger a liquidation or swap that should have been blocked.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Oracle response type ──────────────────────────────────────────────────────

/// Simulated oracle price response.
/// `confidence` is the ± uncertainty around `price` (same units as `price`).
#[contracttype]
#[derive(Clone)]
pub struct OraclePrice {
    pub price: i128,
    pub confidence: i128, // ← ignored by the vulnerable consumer
    pub timestamp: u64,
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    LastPrice,
    Liquidated(Address),
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct OracleConsumer;

#[contractimpl]
impl OracleConsumer {
    /// VULNERABLE: stores the price and marks the actor as liquidated when
    /// price falls below `threshold`, without ever inspecting `oracle.confidence`.
    ///
    /// ❌ BUG: a wide-confidence (unreliable) price passes through identically
    /// to a narrow-confidence (reliable) price — unsafe liquidations can occur.
    pub fn consume_price(env: Env, actor: Address, oracle: OraclePrice, threshold: i128) {
        actor.require_auth();

        // ❌ confidence is destructured away and never checked
        let OraclePrice {
            price,
            confidence: _,   // BUG: silently discarded
            timestamp: _,
        } = oracle;

        env.storage().instance().set(&DataKey::LastPrice, &price);

        if price < threshold {
            env.storage()
                .instance()
                .set(&DataKey::Liquidated(actor), &true);
        }
    }

    pub fn last_price(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::LastPrice)
            .unwrap_or(0)
    }

    pub fn is_liquidated(env: Env, actor: Address) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Liquidated(actor))
            .unwrap_or(false)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, OracleConsumerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, OracleConsumer);
        let client = OracleConsumerClient::new(&env, &id);
        let actor = Address::generate(&env);
        (env, actor, client)
    }

    /// Narrow-confidence price below threshold — liquidation is expected and fine.
    #[test]
    fn test_vulnerable_narrow_confidence_liquidates() {
        let (env, actor, client) = setup();
        let oracle = OraclePrice {
            price: 900,
            confidence: 5,   // 0.5 % of price — reliable
            timestamp: 1000,
        };
        client.consume_price(&actor, &oracle, &1000_i128);
        assert!(client.is_liquidated(&actor));
    }

    /// ❌ Wide-confidence price also triggers liquidation — this is the bug.
    /// A confidence of 200 on a price of 900 means the true price could be
    /// anywhere from 700 to 1100; the liquidation should have been blocked.
    #[test]
    fn test_vulnerable_wide_confidence_still_liquidates() {
        let (env, actor, client) = setup();
        let oracle = OraclePrice {
            price: 900,
            confidence: 200, // ~22 % of price — highly unreliable
            timestamp: 1000,
        };
        // ❌ VULNERABLE: wide confidence is ignored; liquidation fires anyway
        client.consume_price(&actor, &oracle, &1000_i128);
        assert!(client.is_liquidated(&actor));
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    fn setup_secure() -> (Env, Address, secure::SecureOracleConsumerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureOracleConsumer);
        let client = secure::SecureOracleConsumerClient::new(&env, &id);
        let actor = Address::generate(&env);
        (env, actor, client)
    }

    /// Secure path accepts a narrow-confidence price and liquidates correctly.
    #[test]
    fn test_secure_narrow_confidence_liquidates() {
        let (env, actor, client) = setup_secure();
        let oracle = OraclePrice {
            price: 900,
            confidence: 5,
            timestamp: 1000,
        };
        // confidence (5) / price (900) ≈ 0.5 % — well within the 5 % threshold
        client.consume_price(&actor, &oracle, &1000_i128);
        assert!(client.is_liquidated(&actor));
    }

    /// ✅ Secure path rejects a wide-confidence price before acting on it.
    #[test]
    #[should_panic(expected = "price confidence too wide")]
    fn test_secure_wide_confidence_rejected() {
        let (env, actor, client) = setup_secure();
        let oracle = OraclePrice {
            price: 900,
            confidence: 200, // ~22 % — exceeds the 5 % max-confidence threshold
            timestamp: 1000,
        };
        // ✅ SECURE: panics before any liquidation logic runs
        client.consume_price(&actor, &oracle, &1000_i128);
    }

    /// Boundary: confidence exactly at the allowed limit (5 % of price) passes.
    #[test]
    fn test_secure_boundary_confidence_at_limit_passes() {
        let (env, actor, client) = setup_secure();
        // 5 % of 1000 = 50 — exactly at the threshold
        let oracle = OraclePrice {
            price: 1000,
            confidence: 50,
            timestamp: 1000,
        };
        // price (1000) == threshold (1000) → not strictly less, no liquidation
        client.consume_price(&actor, &oracle, &1000_i128);
        assert!(!client.is_liquidated(&actor));
    }

    /// Boundary: confidence one unit above the limit is rejected.
    #[test]
    #[should_panic(expected = "price confidence too wide")]
    fn test_secure_boundary_confidence_just_over_limit_rejected() {
        let (env, actor, client) = setup_secure();
        // 5 % of 1000 = 50; confidence = 51 → just over the limit
        let oracle = OraclePrice {
            price: 1000,
            confidence: 51,
            timestamp: 1000,
        };
        client.consume_price(&actor, &oracle, &1000_i128);
    }
}
