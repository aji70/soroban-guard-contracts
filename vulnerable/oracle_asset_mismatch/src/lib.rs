//! VULNERABLE: Oracle Asset Mismatch
//!
//! A price adapter requests a price for one asset but never verifies that the
//! returned feed's asset id matches the requested asset. An attacker can
//! substitute a high-value feed for a low-value asset, inflating collateral.
//!
//! VULNERABILITY: Oracle response asset id is ignored.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

pub mod secure;

#[contracttype]
pub enum DataKey {
    /// Stores (asset_id, price) for a feed.
    Feed(Symbol),
}

#[contract]
pub struct OracleAssetMismatch;

#[contractimpl]
impl OracleAssetMismatch {
    /// Register a price feed. `feed_asset` is the asset the feed actually tracks.
    pub fn set_feed(env: Env, feed_asset: Symbol, price: i128) {
        env.storage()
            .temporary()
            .set(&DataKey::Feed(feed_asset), &price);
    }

    /// ❌ VULNERABLE: requests price for `requested_asset` but reads from
    /// `feed_asset` without checking they match.
    pub fn get_price_vulnerable(
        env: Env,
        _requested_asset: Symbol,
        feed_asset: Symbol,
    ) -> i128 {
        // BUG: oracle response asset id is ignored — feed_asset is used directly
        // regardless of what was requested.
        env.storage()
            .temporary()
            .get(&DataKey::Feed(feed_asset))
            .unwrap_or(0)
    }

    /// Demonstrate the unsafe path: collateral is valued at the wrong price.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) -> i128 {
        let _ = actor;
        let requested = symbol_short!("LOW");
        let feed = symbol_short!("HIGH");
        let price = Self::get_price_vulnerable(env, requested, feed);
        // Collateral value is inflated because the wrong feed was used.
        price * amount
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> OracleAssetMismatchClient {
        let id = env.register_contract(None, OracleAssetMismatch);
        let client = OracleAssetMismatchClient::new(env, &id);
        // LOW asset worth 1, HIGH asset worth 1_000_000
        client.set_feed(&symbol_short!("LOW"), &1_i128);
        client.set_feed(&symbol_short!("HIGH"), &1_000_000_i128);
        client
    }

    /// Vulnerable path: requesting LOW but reading HIGH feed — accepted silently.
    #[test]
    fn test_vulnerable_accepts_mismatched_feed() {
        let env = Env::default();
        let client = setup(&env);

        let price = client.get_price_vulnerable(&symbol_short!("LOW"), &symbol_short!("HIGH"));
        // ❌ Returns HIGH price for LOW asset — mismatch accepted.
        assert_eq!(price, 1_000_000);
    }

    /// Boundary: requesting and reading the same asset returns the correct price.
    #[test]
    fn test_vulnerable_same_asset_correct() {
        let env = Env::default();
        let client = setup(&env);

        let price = client.get_price_vulnerable(&symbol_short!("LOW"), &symbol_short!("LOW"));
        assert_eq!(price, 1);
    }

    /// Secure path: mismatched asset id is rejected.
    #[test]
    #[should_panic(expected = "asset mismatch")]
    fn test_secure_rejects_mismatch() {
        use crate::secure::SecureOracleClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureOracle);
        let client = SecureOracleClient::new(&env, &id);
        client.set_feed(&symbol_short!("LOW"), &1_i128);
        client.set_feed(&symbol_short!("HIGH"), &1_000_000_i128);

        // ✅ Must panic — requested LOW but feed is HIGH.
        client.get_price(&symbol_short!("LOW"), &symbol_short!("HIGH"));
    }

    /// Secure path: matching asset id succeeds.
    #[test]
    fn test_secure_accepts_matching_asset() {
        use crate::secure::SecureOracleClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureOracle);
        let client = SecureOracleClient::new(&env, &id);
        client.set_feed(&symbol_short!("LOW"), &1_i128);

        let price = client.get_price(&symbol_short!("LOW"), &symbol_short!("LOW"));
        assert_eq!(price, 1);
    }

    /// Demonstrate vulnerable_entry inflates collateral via wrong feed.
    #[test]
    fn test_vulnerable_entry_inflated_collateral() {
        let env = Env::default();
        let client = setup(&env);
        let actor = Address::generate(&env);
        env.mock_all_auths();

        let collateral = client.vulnerable_entry(&actor, &10_i128);
        // ❌ 10 units of LOW valued at HIGH price = 10_000_000 instead of 10.
        assert_eq!(collateral, 10_000_000);
    }
}
