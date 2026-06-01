//! SECURE: Severity Registry with Reputation-Gated Reporting
//!
//! FIXES APPLIED:
//! 1. `report` checks the scanner's stored reputation before accepting any
//!    severity claim. Scanners below `MIN_REPUTATION` are rejected outright.
//! 2. This separates "claimed" severity from "confirmed" severity — only
//!    reputable scanners can affect the stored risk score.

use super::{DataKey, MIN_REPUTATION};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureRegistry;

#[contractimpl]
impl SecureRegistry {
    /// Increment a scanner's reputation (admin action, simplified for fixture).
    pub fn add_reputation(env: Env, scanner: Address, delta: i32) {
        let key = DataKey::Reputation(scanner);
        let current: i32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + delta));
    }

    /// Returns the current reputation of `scanner`.
    pub fn get_reputation(env: Env, scanner: Address) -> i32 {
        env.storage()
            .persistent()
            .get(&DataKey::Reputation(scanner))
            .unwrap_or(0)
    }

    /// SECURE: only accepts severity reports from scanners whose reputation
    /// meets or exceeds `MIN_REPUTATION`.
    ///
    /// # Panics
    /// - If the scanner's reputation is below `MIN_REPUTATION`.
    pub fn report(env: Env, scanner: Address, target: Address, severity: u32) {
        scanner.require_auth();

        // ✅ FIX: Gate on scanner reputation before accepting the report.
        let rep: i32 = env
            .storage()
            .persistent()
            .get(&DataKey::Reputation(scanner.clone()))
            .unwrap_or(0);
        assert!(rep >= MIN_REPUTATION, "scanner reputation too low");

        env.storage()
            .persistent()
            .set(&DataKey::Risk(target), &severity);
    }

    /// Returns the stored risk score for `target`, defaulting to 0.
    pub fn get_risk(env: Env, target: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Risk(target))
            .unwrap_or(0)
    }
}
