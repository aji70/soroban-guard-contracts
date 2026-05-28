//! VULNERABLE: Slash Without Evidence
//!
//! A scanner-registry contract where the admin can slash (confiscate) a
//! scanner's staked tokens based solely on their own authority — no evidence
//! record, report ID, or dispute status is required. This creates an unsafe
//! discretionary loss path and produces no auditable trail.
//!
//! VULNERABILITY: `slash` moves stake based only on `admin.require_auth()`.
//! There is no check that a finalized evidence record exists for the scanner
//! before the slash is executed.
//!
//! Severity: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// Staked token balance for a scanner.
    Stake(Address),
    /// Treasury balance (receives slashed tokens).
    Treasury,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableSlash;

#[contractimpl]
impl VulnerableSlash {
    /// One-time initialisation.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Register a scanner with an initial stake.
    pub fn register_scanner(env: Env, scanner: Address, stake: i128) {
        scanner.require_auth();
        assert!(stake > 0, "stake must be positive");
        env.storage()
            .persistent()
            .set(&DataKey::Stake(scanner.clone()), &stake);
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("staked")), (scanner, stake));
    }

    /// VULNERABLE: slash `amount` from `scanner`'s stake with no evidence check.
    ///
    /// The admin can call this at any time for any reason. There is no
    /// requirement that a finalized evidence record exists, making this an
    /// unsafe discretionary loss path with no auditability.
    ///
    /// # Vulnerability
    /// Missing: evidence record lookup and finalization check before moving stake.
    pub fn slash(env: Env, scanner: Address, amount: i128) {
        Self::require_admin(&env);
        // ❌ Missing: verify a finalized evidence record exists for `scanner`.

        let stake: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(scanner.clone()))
            .unwrap_or(0);

        assert!(amount > 0, "slash amount must be positive");
        assert!(stake >= amount, "insufficient stake to slash");

        env.storage()
            .persistent()
            .set(&DataKey::Stake(scanner.clone()), &(stake - amount));

        let treasury: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Treasury)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Treasury, &(treasury + amount));

        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("slashed")), (scanner, amount));
    }

    pub fn get_stake(env: Env, scanner: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(scanner))
            .unwrap_or(0)
    }

    pub fn get_treasury(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Treasury)
            .unwrap_or(0)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableSlash);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);
        VulnerableSlashClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, scanner)
    }

    /// Normal: scanner registers stake successfully.
    #[test]
    fn test_register_scanner_stores_stake() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = VulnerableSlashClient::new(&env, &contract_id);
        client.register_scanner(&scanner, &1000);
        assert_eq!(client.get_stake(&scanner), 1000);
    }

    /// DEMONSTRATES VULNERABILITY: admin slashes scanner with no evidence record.
    ///
    /// The slash succeeds even though no report or dispute was ever filed.
    #[test]
    fn test_slash_succeeds_without_evidence() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = VulnerableSlashClient::new(&env, &contract_id);

        client.register_scanner(&scanner, &1000);

        // No evidence record created — slash proceeds anyway.
        client.slash(&scanner, &400);

        assert_eq!(
            client.get_stake(&scanner),
            600,
            "stake was slashed without any evidence record"
        );
        assert_eq!(client.get_treasury(), 400);
    }

    /// Boundary: slashing more than the available stake panics.
    #[test]
    #[should_panic(expected = "insufficient stake to slash")]
    fn test_slash_exceeds_stake_panics() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = VulnerableSlashClient::new(&env, &contract_id);
        client.register_scanner(&scanner, &100);
        client.slash(&scanner, &500);
    }

    /// Secure version requires a finalized evidence record before slashing.
    #[test]
    #[should_panic(expected = "no finalized evidence")]
    fn test_secure_rejects_slash_without_evidence() {
        use crate::secure::SecureSlashClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureSlash);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);

        let client = SecureSlashClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.register_scanner(&scanner, &1000);

        // No evidence submitted — secure contract must reject this.
        client.slash(&scanner, &400);
    }

    /// Secure version allows slash when finalized evidence exists.
    #[test]
    fn test_secure_slash_with_evidence_succeeds() {
        use crate::secure::SecureSlashClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureSlash);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);

        let client = SecureSlashClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.register_scanner(&scanner, &1000);

        // Admin submits and finalizes evidence before slashing.
        let report_id: u64 = 42;
        client.submit_evidence(&scanner, &report_id);
        client.finalize_evidence(&report_id);

        client.slash(&scanner, &400);
        assert_eq!(client.get_stake(&scanner), 600);
    }
}
