//! VULNERABLE: Verifier Threshold Ignored
//!
//! A report-verification contract lets an admin configure a required approval
//! threshold, but `finalize_report` only checks that at least one verifier has
//! approved. Reports can be finalized long before the configured quorum is met.
//!
//! VULNERABILITY: `finalize_report` compares `approvals > 0` instead of
//! `approvals >= threshold`, so a single approval is always sufficient
//! regardless of the stored threshold.
//!
//! SECURE MIRROR: `secure::SecureReportRegistry` requires
//! `approvals >= threshold` and rejects a zero threshold at configuration time.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    Threshold,
    Approvals(u64), // report_id -> approval count
    Finalized(u64), // report_id -> bool
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableReportRegistry;

#[contractimpl]
impl VulnerableReportRegistry {
    /// Store the required approval threshold. Any value is accepted, including zero.
    pub fn set_threshold(env: Env, admin: Address, threshold: u32) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Threshold, &threshold);
    }

    /// Record one approval for `report_id` from `verifier`.
    pub fn approve(env: Env, verifier: Address, report_id: u64) {
        verifier.require_auth();
        let key = DataKey::Approvals(report_id);
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));
    }

    /// VULNERABLE: checks `approvals > 0` instead of `approvals >= threshold`.
    ///
    /// # Vulnerability
    /// A single approval finalizes any report regardless of the configured
    /// threshold. Impact: reports can be finalized with insufficient quorum.
    pub fn finalize_report(env: Env, report_id: u64) {
        let approvals: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Approvals(report_id))
            .unwrap_or(0);

        // ❌ BUG: should be `approvals >= threshold`, not `approvals > 0`.
        if approvals == 0 {
            panic!("no approvals");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Finalized(report_id), &true);
    }

    pub fn is_finalized(env: Env, report_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Finalized(report_id))
            .unwrap_or(false)
    }

    pub fn approval_count(env: Env, report_id: u64) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Approvals(report_id))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableReportRegistryClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableReportRegistry);
        let client = VulnerableReportRegistryClient::new(&env, &id);
        let admin = Address::generate(&env);
        // Configure threshold = 3; only 1 approval will be submitted.
        client.set_threshold(&admin, &3);
        (env, client, admin)
    }

    /// Demonstrates the vulnerability: one approval finalizes despite threshold=3.
    #[test]
    fn test_vulnerable_one_approval_finalizes_with_threshold_three() {
        let (env, client, _admin) = setup();
        let verifier = Address::generate(&env);
        let report_id: u64 = 1;

        client.approve(&verifier, &report_id);
        assert_eq!(client.approval_count(&report_id), 1);

        // ❌ Finalization succeeds with only 1 of 3 required approvals.
        client.finalize_report(&report_id);
        assert!(client.is_finalized(&report_id));
    }

    /// Boundary: zero approvals still panics (the only guard that exists).
    #[test]
    #[should_panic(expected = "no approvals")]
    fn test_vulnerable_zero_approvals_panics() {
        let (env, client, _admin) = setup();
        client.finalize_report(&42);
    }

    /// Secure version: one approval is not enough when threshold is three.
    #[test]
    #[should_panic(expected = "threshold not met")]
    fn test_secure_rejects_finalization_below_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureReportRegistry);
        let client = secure::SecureReportRegistryClient::new(&env, &id);
        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let report_id: u64 = 1;

        client.set_threshold(&admin, &3);
        client.approve(&verifier, &report_id);

        // Must panic — only 1 of 3 approvals present.
        client.finalize_report(&report_id);
    }

    /// Secure version: exactly three approvals allows finalization.
    #[test]
    fn test_secure_accepts_finalization_at_threshold() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureReportRegistry);
        let client = secure::SecureReportRegistryClient::new(&env, &id);
        let admin = Address::generate(&env);
        let report_id: u64 = 2;

        client.set_threshold(&admin, &3);
        for _ in 0..3 {
            let v = Address::generate(&env);
            client.approve(&v, &report_id);
        }

        client.finalize_report(&report_id);
        assert!(client.is_finalized(&report_id));
    }
}
