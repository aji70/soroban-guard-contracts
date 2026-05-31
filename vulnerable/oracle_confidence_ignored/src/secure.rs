//! SECURE mirror: reject prices whose confidence exceeds MAX_CONFIDENCE_BPS
//! basis points relative to the price before acting on them.
//!
//! ✅ FIX: `consume_price` checks `confidence * 10_000 / price <= MAX_CONFIDENCE_BPS`
//! and panics with "price confidence too wide" when the feed is unreliable.

use crate::{DataKey, OraclePrice};
use soroban_sdk::{contract, contractimpl, Address, Env};

/// Maximum acceptable confidence expressed in basis points (1 bp = 0.01 %).
/// 500 bp = 5 % — prices with wider uncertainty are rejected.
const MAX_CONFIDENCE_BPS: i128 = 500;

#[contract]
pub struct SecureOracleConsumer;

#[contractimpl]
impl SecureOracleConsumer {
    /// ✅ SECURE: validates confidence before consuming the price.
    ///
    /// Rejects the call when `(confidence / price) * 10_000 > MAX_CONFIDENCE_BPS`.
    pub fn consume_price(env: Env, actor: Address, oracle: OraclePrice, threshold: i128) {
        actor.require_auth();

        let OraclePrice {
            price,
            confidence,
            timestamp: _,
        } = oracle.clone();

        // Guard: price must be positive to avoid division issues
        if price <= 0 {
            panic!("invalid price");
        }

        // ✅ Reject if confidence band is too wide relative to price
        let confidence_bps = confidence.checked_mul(10_000)
            .expect("confidence overflow") / price;
        if confidence_bps > MAX_CONFIDENCE_BPS {
            panic!("price confidence too wide");
        }

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
