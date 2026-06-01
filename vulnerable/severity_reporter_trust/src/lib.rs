//! VULNERABLE: Severity Reporter Trust — Unweighted Risk Aggregation
//!
//! A registry that computes contract risk directly from the severity claimed by
//! any scanner, regardless of that scanner's reputation. A low-reputation or
//! unverified scanner can submit a "critical" report and immediately inflate the
//! stored risk score, or submit a "none" report to deflate it.
//!
//! VULNERABILITY: Claimed severity is accepted as aggregate risk without any
//! reputation weighting — missing reputation gate before `risk` is updated.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

/// Reputation threshold a scanner must meet before its reports affect risk.
pub const MIN_REPUTATION: i32 = 10;

/// Severity levels a scanner can claim (stored as u32 for simplicity).
/// 0 = None, 1 = Low, 2 = Medium, 3 = High, 4 = Critical
pub const SEV_NONE: u32 = 0;
pub const SEV_LOW: u32 = 1;
pub const SEV_MEDIUM: u32 = 2;
pub const SEV_HIGH: u32 = 3;
pub const SEV_CRITICAL: u32 = 4;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Aggregated risk score for a contract address.
    Risk(Address),
    /// Reputation score for a scanner address (i32, starts at 0).
    Reputation(Address),
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct SeverityRegistry;

#[contractimpl]
impl SeverityRegistry {
    /// Increment a scanner's reputation (admin action, simplified for fixture).
    pub fn add_reputation(env: Env, scanner: Address, delta: i32) {
        let key = DataKey::Reputation(scanner);
        let current: i32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &(current + delta));
    }

    /// Returns the current reputation of `scanner`.
    pub fn get_reputation(env: Env, scanner: Address) -> i32 {
        env.storage()
            .persistent()
            .get(&DataKey::Reputation(scanner))
            .unwrap_or(0)
    }

    /// VULNERABLE: accepts claimed `severity` from any scanner and immediately
    /// overwrites the stored risk for `target` — no reputation check.
    ///
    /// # Vulnerability
    /// Missing `assert!(reputation >= MIN_REPUTATION)` before updating risk.
    /// Impact: any unverified scanner can set risk to any value, inflating or
    /// deflating scores and corrupting downstream risk decisions.
    pub fn report(env: Env, scanner: Address, target: Address, severity: u32) {
        scanner.require_auth();
        // ❌ Missing: reputation gate before accepting the report.
        // let rep: i32 = env.storage().persistent().get(&DataKey::Reputation(scanner.clone())).unwrap_or(0);
        // assert!(rep >= MIN_REPUTATION, "scanner reputation too low");
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

    /// Fixture entry matching the issue's vulnerable pattern signature.
    ///
    /// # Vulnerability
    /// BUG: claimed severity is accepted as aggregate risk without weighting.
    /// The fixture makes this unsafe path reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        // BUG: `amount` is treated as a severity level and stored directly as
        // risk with no reputation check on `actor`.
        let severity = if amount >= SEV_CRITICAL as i128 {
            SEV_CRITICAL
        } else if amount > 0 {
            amount as u32
        } else {
            SEV_NONE
        };
        // ❌ No reputation gate — any actor can set risk to any severity.
        env.storage()
            .persistent()
            .set(&DataKey::Risk(actor), &severity);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureRegistryClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SeverityRegistry);
        (env, id)
    }

    // ── Vulnerable path ───────────────────────────────────────────────────────

    /// Demonstrates the vulnerability: an untrusted scanner (reputation = 0)
    /// submits a critical report and the risk score changes immediately.
    #[test]
    fn test_vulnerable_untrusted_scanner_inflates_risk() {
        let (env, id) = setup();
        let client = SeverityRegistryClient::new(&env, &id);
        let untrusted = Address::generate(&env);
        let target = Address::generate(&env);

        // Scanner has zero reputation — should be blocked by a secure contract.
        assert_eq!(client.get_reputation(&untrusted), 0);

        // ❌ Vulnerable path: critical severity accepted with no reputation check.
        client.report(&untrusted, &target, &SEV_CRITICAL);
        assert_eq!(client.get_risk(&target), SEV_CRITICAL);
    }

    /// Boundary condition: a scanner just below MIN_REPUTATION can still
    /// manipulate risk in the vulnerable contract.
    #[test]
    fn test_vulnerable_below_threshold_accepted() {
        let (env, id) = setup();
        let client = SeverityRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);
        let target = Address::generate(&env);

        // Give the scanner reputation = MIN_REPUTATION - 1 (just below threshold).
        client.add_reputation(&scanner, &(MIN_REPUTATION - 1));
        assert_eq!(client.get_reputation(&scanner), MIN_REPUTATION - 1);

        // ❌ Vulnerable: still accepted even though reputation is below threshold.
        client.report(&scanner, &target, &SEV_HIGH);
        assert_eq!(client.get_risk(&target), SEV_HIGH);
    }

    // ── Secure path ───────────────────────────────────────────────────────────

    /// Secure implementation rejects a report from a scanner below MIN_REPUTATION.
    #[test]
    #[should_panic]
    fn test_secure_rejects_low_reputation_scanner() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = SecureRegistryClient::new(&env, &id);
        let untrusted = Address::generate(&env);
        let target = Address::generate(&env);

        // Scanner has zero reputation — secure contract must reject this.
        client.report(&untrusted, &target, &SEV_CRITICAL);
    }

    /// Secure implementation accepts a report from a scanner at or above MIN_REPUTATION.
    #[test]
    fn test_secure_accepts_reputable_scanner() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = SecureRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);
        let target = Address::generate(&env);

        // Bring scanner up to exactly the threshold.
        client.add_reputation(&scanner, &MIN_REPUTATION);

        // ✅ Secure path: report accepted because reputation meets the threshold.
        client.report(&scanner, &target, &SEV_MEDIUM);
        assert_eq!(client.get_risk(&target), SEV_MEDIUM);
    }

    /// Secure implementation rejects a scanner that is exactly one point below threshold.
    #[test]
    #[should_panic]
    fn test_secure_rejects_one_below_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = SecureRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);
        let target = Address::generate(&env);

        client.add_reputation(&scanner, &(MIN_REPUTATION - 1));

        // ✅ Secure path: panics — one point below threshold is still rejected.
        client.report(&scanner, &target, &SEV_HIGH);
    }
}
