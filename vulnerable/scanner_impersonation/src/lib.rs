//! VULNERABLE: Scanner Impersonation
//!
//! A registry variant where `submit_scan(scanner, ...)` does **not** call
//! `scanner.require_auth()`. Any caller can pass an arbitrary `scanner`
//! address and submit findings attributed to that address, poisoning the
//! registry with fake results.
//!
//! VULNERABILITY: Missing `scanner.require_auth()` in `submit_scan`.
//! Severity: High
//!
//! Secure mirror: `registry/src/lib.rs` which correctly calls
//! `scanner.require_auth()` before accepting a submission.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map, String, Vec};

pub mod secure;

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct ScanResult {
    pub scanner: Address,
    pub timestamp: u64,
    pub findings_hash: String,
    pub severity_counts: Map<String, u32>,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Scanner(Address),
    LatestScan(Address),
    ScanHistory(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableRegistry;

#[contractimpl]
impl VulnerableRegistry {
    /// Initialise the registry with an admin address. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Register `scanner` as an approved scanner. Requires admin auth.
    pub fn add_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner), &true);
    }

    /// Returns `true` if `scanner` is in the approved scanner list.
    pub fn is_scanner(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Scanner(scanner))
            .unwrap_or(false)
    }

    /// VULNERABLE: accepts any `scanner` address without verifying the caller
    /// controls that address. No `scanner.require_auth()` call.
    pub fn submit_scan(
        env: Env,
        scanner: Address,
        contract_address: Address,
        findings_hash: String,
        severity_counts: Map<String, u32>,
    ) {
        // ❌ Missing: scanner.require_auth();

        // Still checks the approved list, but an attacker can impersonate any
        // approved scanner address without holding its private key.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("not a verified scanner");
        }

        let result = ScanResult {
            scanner,
            timestamp: env.ledger().timestamp(),
            findings_hash,
            severity_counts,
        };

        env.storage()
            .persistent()
            .set(&DataKey::LatestScan(contract_address.clone()), &result);

        let history_key = DataKey::ScanHistory(contract_address);
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(&env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);
    }

    /// Returns the latest scan result for `contract_address`, or `None`.
    pub fn get_scan(env: Env, contract_address: Address) -> Option<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::LatestScan(contract_address))
    }

    /// Returns the full scan history for `contract_address`, or an empty vec.
    pub fn get_history(env: Env, contract_address: Address) -> Vec<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env))
    }

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
    use soroban_sdk::{map, testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);
        VulnerableRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, scanner)
    }

    fn counts(env: &Env) -> Map<String, u32> {
        map![env, (String::from_str(env, "high"), 1u32)]
    }

    /// Legitimate scanner submits a result normally.
    #[test]
    fn test_legitimate_scanner_submits() {
        let (env, contract_id, scanner) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        client.add_scanner(&scanner);
        client.submit_scan(
            &scanner,
            &target,
            &String::from_str(&env, "hash1"),
            &counts(&env),
        );

        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.scanner, scanner);
        assert_eq!(result.findings_hash, String::from_str(&env, "hash1"));
    }

    /// Demonstrates the vulnerability: an attacker submits a result attributed
    /// to a different (approved) scanner address without holding its key.
    /// Because `scanner.require_auth()` is absent, this succeeds.
    #[test]
    fn test_attacker_impersonates_scanner() {
        let (env, contract_id, legitimate_scanner) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        // Register the legitimate scanner.
        client.add_scanner(&legitimate_scanner);

        // Attacker passes `legitimate_scanner` as the `scanner` argument but
        // is a completely different address. No auth check stops them.
        let fake_hash = String::from_str(&env, "attacker_fabricated_hash");
        client.submit_scan(&legitimate_scanner, &target, &fake_hash, &counts(&env));

        // The poisoned result is now stored under the legitimate scanner's name.
        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.scanner, legitimate_scanner);
        assert_eq!(result.findings_hash, fake_hash);
    }

    /// Secure version rejects submissions where the caller is not the scanner.
    /// Setup uses mock_all_auths, then we clear auths before the exploit call
    /// so the secure contract's scanner.require_auth() fires and panics.
    #[test]
    #[should_panic]
    fn test_secure_rejects_impersonation() {
        use crate::secure::SecureRegistryClient;

        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureRegistry);
        let admin = Address::generate(&env);
        let legitimate_scanner = Address::generate(&env);

        // Setup: initialize and register scanner with all auths mocked.
        env.mock_all_auths();
        SecureRegistryClient::new(&env, &contract_id).initialize(&admin);
        SecureRegistryClient::new(&env, &contract_id).add_scanner(&legitimate_scanner);

        // Clear all mocked auths — now require_auth() will actually enforce.
        env.set_auths(&[]);
        let target = Address::generate(&env);
        // No auth provided for `legitimate_scanner` → secure contract panics.
        SecureRegistryClient::new(&env, &contract_id).submit_scan(
            &legitimate_scanner,
            &target,
            &String::from_str(&env, "fake"),
            &map![&env, (String::from_str(&env, "critical"), 99u32)],
        );
    }
}
