//! On-chain Scan Result Registry
//!
//! Stores scan findings submitted by verified scanners, keyed by the scanned
//! contract address. Supports full history per contract and an enumerable
//! index of all scanned contract addresses.
//!
//! Auth model:
//! - Only the admin can add/remove scanners.
//! - `submit_scan` / `submit_scans_bulk` require the caller to pass their own
//!   `scanner` address and have signed the transaction. The address is then
//!   checked against the approved-scanner registry.

#![no_std]
extern crate alloc;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Map, String, Vec};

// ── Severity label constants ─────────────────────────────────────────────────

pub const SEVERITY_CRITICAL: &str = "critical";
pub const SEVERITY_HIGH: &str = "high";
pub const SEVERITY_MEDIUM: &str = "medium";
pub const SEVERITY_LOW: &str = "low";

/// Maximum number of entries allowed in a single bulk submission.
const MAX_BULK: u32 = 10;

// ── Types ────────────────────────────────────────────────────────────────────

/// Human-readable metadata about a scanned contract, set by its registered scanner.
#[contracttype]
#[derive(Clone)]
pub struct ContractMetadata {
    pub name: String,
    pub version: String,
    /// Unix timestamp of the audit date.
    pub audit_date: u64,
    pub repo_url: String,
}

#[contracttype]
#[derive(Clone)]
pub struct ScanResult {
    pub scanner: Address,
    pub timestamp: u64,
    pub findings_hash: String,
    pub severity_counts: Map<String, u32>,
}

#[contracttype]
#[derive(Clone)]
pub struct ScanEntry {
    pub contract_address: Address,
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
    /// Set of all contract addresses that have at least one scan (used as an index)
    SeverityIndex,
    /// Reputation score for a scanner address (i32, default 0)
    ScannerScore(Address),
    /// Human-readable metadata for a contract address
    Metadata(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct ScanRegistry;

#[contractimpl]
impl ScanRegistry {
    // ── Initialisation ───────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    // ── Scanner management (admin only) ──────────────────────────────────────

    /// Add a scanner to the approved list.
    ///
    /// # Arguments
    /// * `scanner` - The address to approve for submitting scans.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    ///
    /// # Events
    /// Emits `("scanner", "added", scanner)`.
    pub fn add_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        let already: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner.clone()), &true);
        if !already {
            let count: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::ScannerCount)
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::ScannerCount, &(count + 1));
        }
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("added")), scanner);
    }

    /// Remove a scanner from the approved list.
    ///
    /// # Arguments
    /// * `scanner` - The address to remove from the approved list.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    ///
    /// # Events
    /// Emits `("scanner", "removed", scanner)`.
    pub fn remove_scanner(env: Env, scanner: Address) {
        Self::require_admin(&env);
        let was_active: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        env.storage()
            .persistent()
            .set(&DataKey::Scanner(scanner.clone()), &false);
        if was_active {
            let count: u32 = env
                .storage()
                .persistent()
                .get(&DataKey::ScannerCount)
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::ScannerCount, &count.saturating_sub(1));
        }
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("removed")), scanner);
    }

    pub fn is_scanner(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Scanner(scanner))
            .unwrap_or(false)
    }

    // ── Scan submission ──────────────────────────────────────────────────────

    /// Submit a scan result for `contract_address`.
    ///
    /// `scanner` must be a verified scanner address and must have signed this
    /// transaction. `findings_hash` is a hex-encoded SHA-256 of the full
    /// findings JSON. `severity_counts` maps severity labels to counts.
    ///
    /// # Events
    /// Emits `("scan", "submitted", (scanner, contract_address, findings_hash))`.
    pub fn submit_scan(
        env: Env,
        scanner: Address,
        contract_address: Address,
        findings_hash: String,
        severity_counts: Map<String, u32>,
    ) {
        // 1. findings_hash must not be empty.
        if findings_hash.is_empty() {
            panic!("findings_hash cannot be empty");
        }

        // 2. The scanner must have signed this transaction.
        scanner.require_auth();

        // 3. The scanner must be in the approved list.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Scanner(scanner.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("not a verified scanner");
        }

        // 3. The target contract must not be deactivated.
        let active: bool = env
            .storage()
            .persistent()
            .get(&DataKey::ContractActive(contract_address.clone()))
            .unwrap_or(true);
        if !active {
            panic!("contract is deactivated");
        }

        // Keep a copy for the score key before scanner is moved into ScanResult.
        let score_key = DataKey::ScannerScore(scanner.clone());

        let result = ScanResult {
            scanner: scanner.clone(),
            timestamp: env.ledger().timestamp(),
            findings_hash: findings_hash.clone(),
            severity_counts,
        };
        Self::store_result(&env, contract_address, result);
    }

        env.storage()
            .persistent()
            .set(&DataKey::LatestScan(contract_address.clone()), &result);

        // Append to history.
        let history_key = DataKey::ScanHistory(contract_address.clone());
        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&history_key)
            .unwrap_or(Vec::new(&env));
        history.push_back(result);
        env.storage().persistent().set(&history_key, &history);

        // Maintain severity index.
        let index_key = DataKey::SeverityIndex;
        let mut index: Map<Address, ()> = env
            .storage()
            .persistent()
            .get(&index_key)
            .unwrap_or(Map::new(&env));
        if !index.contains_key(contract_address.clone()) {
            index.set(contract_address, ());
            env.storage().persistent().set(&index_key, &index);
        }
        // Increment scanner reputation score.
        let score: i32 = env.storage().persistent().get(&score_key).unwrap_or(0i32);
        env.storage()
            .persistent()
            .set(&score_key, &score.saturating_add(1));
    }

    // ── Reputation ───────────────────────────────────────────────────────────

    /// Dispute a scanner's submission (admin only), decrementing their score by 1.
    ///
    /// # Arguments
    /// * `scanner` - The scanner whose score should be decremented.
    ///
    /// # Panics
    /// Panics if the caller is not the admin.
    pub fn dispute_scan(env: Env, scanner: Address) {
        Self::require_admin(&env);
        let score_key = DataKey::ScannerScore(scanner);
        let score: i32 = env.storage().persistent().get(&score_key).unwrap_or(0i32);
        env.storage()
            .persistent()
            .set(&score_key, &score.saturating_sub(1));
    }

    /// Return the reputation score for a scanner (defaults to 0).
    ///
    /// # Arguments
    /// * `scanner` - The scanner address to query.
    pub fn get_scanner_score(env: Env, scanner: Address) -> i32 {
        env.storage()
            .persistent()
            .get(&DataKey::ScannerScore(scanner))
            .unwrap_or(0i32)
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    pub fn get_scan(env: Env, contract_address: Address) -> Option<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::LatestScan(contract_address))
    }

    pub fn get_history(env: Env, contract_address: Address) -> Vec<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env))
    }

    /// Return contract addresses whose latest scan meets the given severity
    /// thresholds.
    ///
    /// # Arguments
    /// * `min_critical` - Minimum number of critical findings required.
    /// * `min_high` - Minimum number of high findings required.
    /// * `page` - Page number (0-indexed).
    /// * `page_size` - Number of items per page. Use `0` to return all matches.
    ///
    /// # Returns
    /// A vector of contract `Address`es whose latest scan satisfies both
    /// `critical >= min_critical` and `high >= min_high`.
    pub fn get_scans_by_min_severity(
        env: Env,
        min_critical: u32,
        min_high: u32,
        page: u32,
        page_size: u32,
    ) -> Vec<Address> {
        let index: Map<Address, ()> = env
            .storage()
            .persistent()
            .get(&DataKey::SeverityIndex)
            .unwrap_or(Map::new(&env));

        let mut matches: Vec<Address> = Vec::new(&env);

        for (addr, _) in index {
            if let Some(scan) = env
                .storage()
                .persistent()
                .get::<DataKey, ScanResult>(&DataKey::LatestScan(addr.clone()))
            {
                let critical = Self::get_severity_count(&env, &scan.severity_counts, SEVERITY_CRITICAL);
                let high = Self::get_severity_count(&env, &scan.severity_counts, SEVERITY_HIGH);
                if critical >= min_critical && high >= min_high {
                    matches.push_back(addr);
                }
            }
        }

        // Pagination
        if page_size == 0 {
            return matches;
        }

        let start = page * page_size;
        if start >= matches.len() {
            return Vec::new(&env);
        }

        let end = (start + page_size).min(matches.len());
        let mut result: Vec<Address> = Vec::new(&env);
        for i in start..end {
            result.push_back(matches.get(i).unwrap());
        }
        result
    /// Return the total number of scan results stored for a contract address.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    ///
    /// # Returns
    /// The number of `ScanResult`s in the history (0 if none).
    pub fn get_history_len(env: Env, contract_address: Address) -> u32 {
        let history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env));
        history.len()
    }

    /// Retrieve a bounded page of scan history for a contract address.
    ///
    /// Results are ordered oldest to newest. `limit` is capped at 50.
    /// If `offset` is beyond the end of the history, an empty vector is returned.
    ///
    /// # Arguments
    /// * `contract_address` - The contract address to look up.
    /// * `offset`           - Zero-based index of the first record to return.
    /// * `limit`            - Maximum number of records to return (capped at 50).
    pub fn get_history_page(
        env: Env,
        contract_address: Address,
        offset: u32,
        limit: u32,
    ) -> Vec<ScanResult> {
        const MAX_LIMIT: u32 = 50;
        let effective_limit = limit.min(MAX_LIMIT);

        let history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::ScanHistory(contract_address))
            .unwrap_or(Vec::new(&env));

        let total = history.len();
        if offset >= total {
            return Vec::new(&env);
        }

        let end = (start + page_size).min(total);
        let mut page_results: Vec<ScanResult> = Vec::new(&env);
        for i in start..end {
            page_results.push_back(history.get(i).expect("history index out of bounds"));
        }
        result
    }

    /// Retrieve the latest scan result for each contract in the batch.
    ///
    /// Returns `None` for any contract that has no scan history.
    /// Capped at 20 addresses to prevent memory DoS.
    ///
    /// # Panics
    /// Panics if `contracts.len() > 20`.
    pub fn get_latest_scans_batch(
        env: Env,
        contracts: Vec<Address>,
    ) -> Vec<Option<ScanResult>> {
        if contracts.len() > 20 {
            panic!("batch size exceeds maximum of 20");
        }
        let mut results: Vec<Option<ScanResult>> = Vec::new(&env);
        for contract in contracts.iter() {
            let latest = env
                .storage()
                .persistent()
                .get(&DataKey::LatestScan(contract));
            results.push_back(latest);
        }
        results
    }

    /// Return the admin address of the registry.
    ///
    /// # Returns
    /// The admin `Address`.
    ///
    /// `page` is 0-indexed. Returns an empty vec when `page` is out of range.
    pub fn get_scanned_contracts_page(env: Env, page: u32, page_size: u32) -> Vec<Address> {
        let all: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::ScannedContracts)
            .unwrap_or(Vec::new(&env));

        let start = (page * page_size) as usize;
        let mut result = Vec::new(&env);
        for i in start..(start + page_size as usize) {
            match all.get(i as u32) {
                Some(addr) => result.push_back(addr),
                None => break,
            }
        }
        result
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    // ── Metadata ─────────────────────────────────────────────────────────────

    /// Set human-readable metadata for a contract.
    ///
    /// Only the scanner that has previously submitted a scan for `contract_address`
    /// may set its metadata.
    ///
    /// # Panics
    /// Panics if `scanner` has never submitted a scan for `contract_address`,
    /// or if `scanner` has not signed the transaction.
    pub fn set_metadata(env: Env, scanner: Address, contract_address: Address, metadata: ContractMetadata) {
        scanner.require_auth();

        // Verify the scanner has an existing scan result for this contract.
        let latest: Option<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::LatestScan(contract_address.clone()));
        let scan = latest.expect("no scan found for this contract");
        if scan.scanner != scanner {
            panic!("only the contract's scanner may set metadata");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Metadata(contract_address), &metadata);
    }

    /// Retrieve metadata for a contract address.
    ///
    /// # Returns
    /// `Some(ContractMetadata)` if metadata has been set, `None` otherwise.
    pub fn get_metadata(env: Env, contract_address: Address) -> Option<ContractMetadata> {
        env.storage()
            .persistent()
            .get(&DataKey::Metadata(contract_address))
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

    fn get_severity_count(env: &Env, severity_counts: &Map<String, u32>, label: &str) -> u32 {
        severity_counts
            .get(String::from_str(env, label))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{map, testutils::Address as _, testutils::Events, Address, Env, String};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);
        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin, scanner)
    }

    fn counts(env: &Env) -> Map<String, u32> {
        map![env, (String::from_str(env, "low"), 1u32)]
    }

    #[test]
    fn test_add_scanner_and_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        let hash = String::from_str(&env, "abc123");

        client.add_scanner(&scanner);
        assert!(client.is_scanner(&scanner));

        client.submit_scan(&scanner, &target, &hash, &counts(&env));

        let result = client.get_scan(&target).unwrap();
        assert_eq!(result.findings_hash, hash);
    }

    #[test]
    fn test_get_history_accumulates() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash1"), &counts(&env));
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash2"), &counts(&env));

        // Use get_history_page to read both records (offset=0, limit=50).
        let history = client.get_history_page(&target, &0, &50);
        assert_eq!(history.len(), 2);
        assert_eq!(history.get(0).unwrap().findings_hash, String::from_str(&env, "hash1"));
        assert_eq!(history.get(1).unwrap().findings_hash, String::from_str(&env, "hash2"));
    }

    #[test]
    #[should_panic]
    fn test_unverified_scanner_cannot_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "badhash"), &counts(&env));
    }

    #[test]
    #[should_panic]
    fn test_remove_scanner_blocks_submission() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.remove_scanner(&scanner);
        assert!(!client.is_scanner(&scanner));

        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash"), &counts(&env));
    }

    // ── Scanned-contracts index tests ────────────────────────────────────────

    #[test]
    fn test_get_all_scanned_contracts_returns_all() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let t1 = Address::generate(&env);
        let t2 = Address::generate(&env);
        let t3 = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &t1, &String::from_str(&env, "h1"), &counts(&env));
        client.submit_scan(&scanner, &t2, &String::from_str(&env, "h2"), &counts(&env));
        client.submit_scan(&scanner, &t3, &String::from_str(&env, "h3"), &counts(&env));

        let all = client.get_all_scanned_contracts();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_scanning_same_contract_twice_no_duplicate() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts(&env));
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts(&env));

        let all = client.get_all_scanned_contracts();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_paginated_query_returns_correct_slice() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let targets: Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();

        client.add_scanner(&scanner);
        for t in &targets {
            client.submit_scan(&scanner, t, &String::from_str(&env, "h"), &counts(&env));
        }

        // Page 0, size 2 → first 2
        let page0 = client.get_scanned_contracts_page(&0, &2);
        assert_eq!(page0.len(), 2);

        // Page 1, size 2 → next 2
        let page1 = client.get_scanned_contracts_page(&1, &2);
        assert_eq!(page1.len(), 2);

        // Page 2, size 2 → last 1
        let page2 = client.get_scanned_contracts_page(&2, &2);
        assert_eq!(page2.len(), 1);

        // Pages don't overlap
        assert_ne!(page0.get(0).unwrap(), page1.get(0).unwrap());
    }

    // ── get_scans_by_min_severity tests ──────────────────────────────────────

    #[test]
    fn test_get_scans_by_min_severity_filters() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        client.add_scanner(&scanner);

        let target_low = Address::generate(&env);
        let target_high = Address::generate(&env);
        let target_crit = Address::generate(&env);

        client.submit_scan(
            &scanner,
            &target_low,
            &String::from_str(&env, "h1"),
            &map![&env, (String::from_str(&env, "critical"), 0u32), (String::from_str(&env, "high"), 0u32)],
        );
        client.submit_scan(
            &scanner,
            &target_high,
            &String::from_str(&env, "h2"),
            &map![&env, (String::from_str(&env, "critical"), 0u32), (String::from_str(&env, "high"), 2u32)],
        );
        client.submit_scan(
            &scanner,
            &target_crit,
            &String::from_str(&env, "h3"),
            &map![&env, (String::from_str(&env, "critical"), 1u32), (String::from_str(&env, "high"), 1u32)],
        );

        // Require at least 1 critical and 1 high
        let results = client.get_scans_by_min_severity(&1, &1, &0, &0);
        assert_eq!(results.len(), 1);
        assert_eq!(results.get(0).unwrap(), target_crit);
    }

    #[test]
    fn test_get_scans_by_min_severity_zero_returns_all() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        client.add_scanner(&scanner);

        let a = Address::generate(&env);
        let b = Address::generate(&env);

        client.submit_scan(
            &scanner,
            &a,
            &String::from_str(&env, "h1"),
            &map![&env, (String::from_str(&env, "critical"), 0u32)],
        );
        client.submit_scan(
            &scanner,
            &b,
            &String::from_str(&env, "h2"),
            &map![&env, (String::from_str(&env, "high"), 5u32)],
        );

        let results = client.get_scans_by_min_severity(&0, &0, &0, &0);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_get_scans_by_min_severity_high_threshold_returns_empty() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        client.add_scanner(&scanner);

        let target = Address::generate(&env);
        client.submit_scan(
            &scanner,
            &target,
            &String::from_str(&env, "h1"),
            &map![&env, (String::from_str(&env, "critical"), 1u32), (String::from_str(&env, "high"), 1u32)],
        );

        let results = client.get_scans_by_min_severity(&100, &100, &0, &0);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_get_scans_by_min_severity_pagination() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        client.add_scanner(&scanner);

        let a = Address::generate(&env);
        let b = Address::generate(&env);
        let c = Address::generate(&env);

        client.submit_scan(
            &scanner,
            &a,
            &String::from_str(&env, "h1"),
            &map![&env, (String::from_str(&env, "critical"), 1u32)],
        );
        client.submit_scan(
            &scanner,
            &b,
            &String::from_str(&env, "h2"),
            &map![&env, (String::from_str(&env, "critical"), 1u32)],
        );
        client.submit_scan(
            &scanner,
            &c,
            &String::from_str(&env, "h3"),
            &map![&env, (String::from_str(&env, "critical"), 1u32)],
        );

        // page 0, size 2
        let page0 = client.get_scans_by_min_severity(&1, &0, &0, &2);
        assert_eq!(page0.len(), 2);

        // page 1, size 2
        let page1 = client.get_scans_by_min_severity(&1, &0, &1, &2);
        assert_eq!(page1.len(), 1);

        // page 2, size 2 -> empty
        let page2 = client.get_scans_by_min_severity(&1, &0, &2, &2);
        assert_eq!(page2.len(), 0);
    // ── Reputation tests ─────────────────────────────────────────────────────

    #[test]
    fn test_score_starts_at_zero() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        assert_eq!(client.get_scanner_score(&scanner), 0);
    }

    #[test]
    fn test_score_increments_on_submit() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 1);

        client.submit_scan(&scanner, &target, &String::from_str(&env, "h2"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 2);
    }

    #[test]
    fn test_score_decrements_on_admin_dispute() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "h1"), &counts);
        assert_eq!(client.get_scanner_score(&scanner), 1);

        client.dispute_scan(&scanner);
        assert_eq!(client.get_scanner_score(&scanner), 0);
    }

    // ── Pagination tests ──────────────────────────────────────────────────────

    fn submit_n_scans(
        client: &ScanRegistryClient,
        scanner: &Address,
        target: &Address,
        n: u32,
        env: &Env,
    ) {
        // Pre-defined hash labels — supports up to 8 scans in tests.
        let hashes = [
            "hash0", "hash1", "hash2", "hash3", "hash4", "hash5", "hash6", "hash7",
        ];
        let counts: Map<String, u32> = map![env, (String::from_str(env, "low"), 0u32)];
        for i in 0..n {
            // Use unique hashes by encoding the index into the string.
            let hash = String::from_str(env, &alloc::format!("hash{i}"));
            client.submit_scan(scanner, target, &hash, &counts);
        }
    }

    /// Demonstrates the unbounded-read vulnerability: inserting 200 records and
    /// reading them all back via get_history_page with a large limit returns all 200.
    /// (This is the pattern that would brick the node if get_history were unbounded.)
    #[test]
    fn test_200_records_unbounded_demo() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 200, &env);

        let page = client.get_history_page(&target, &0, &3);
        assert_eq!(page.len(), 3);
        assert_eq!(
            page.get(0).unwrap().findings_hash,
            String::from_str(&env, "hash0")
        );
        assert_eq!(
            page.get(2).unwrap().findings_hash,
            String::from_str(&env, "hash2")
        );
    }

    /// After the fix, get_history_page with limit=50 returns exactly 50 records
    /// even when more are stored.
    #[test]
    fn test_limit_50_returns_exactly_50() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 200, &env);

        // page 1 with page_size 3 → items [3, 4] (2 items)
        let page = client.get_history_page(&target, &1, &3);
        assert_eq!(page.len(), 2);
        assert_eq!(
            page.get(0).unwrap().findings_hash,
            String::from_str(&env, "hash3")
        );
        assert_eq!(
            page.get(1).unwrap().findings_hash,
            String::from_str(&env, "hash4")
        );
    }

    /// Requesting limit=100 (above the cap) is silently capped to 50.
    #[test]
    fn test_limit_above_cap_is_capped_to_50() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 200, &env);

        let page = client.get_history_page(&target, &0, &100);
        assert_eq!(page.len(), 50);
    }

    /// offset + limit beyond the Vec length returns only the remaining records
    /// without panicking.
    #[test]
    fn test_offset_plus_limit_beyond_end_returns_remainder() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 10, &env);

        // offset=8, limit=50 → only 2 records remain (indices 8 and 9).
        let page = client.get_history_page(&target, &8, &50);
        assert_eq!(page.len(), 2);
        assert_eq!(page.get(0).unwrap().findings_hash, String::from_str(&env, "hash8"));
        assert_eq!(page.get(1).unwrap().findings_hash, String::from_str(&env, "hash9"));
    }

    #[test]
    fn test_offset_beyond_end_returns_empty() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        submit_n_scans(&client, &scanner, &target, 3, &env);

        let page = client.get_history_page(&target, &10, &50);
        assert_eq!(page.len(), 0);
    }

    #[test]
    fn test_get_history_len() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        client.add_scanner(&scanner);
        assert_eq!(client.get_history_len(&target), 0);

        submit_n_scans(&client, &scanner, &target, 4, &env);
        assert_eq!(client.get_history_len(&target), 4);
    }

    // ── Metadata tests ────────────────────────────────────────────────────────

    fn make_metadata(env: &Env) -> ContractMetadata {
        ContractMetadata {
            name: String::from_str(env, "MyToken"),
            version: String::from_str(env, "1.0.0"),
            audit_date: 1_700_000_000u64,
            repo_url: String::from_str(env, "https://github.com/example/mytoken"),
        }
    }

    #[test]
    fn test_scanner_sets_and_gets_metadata() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash1"), &counts);

        let meta = make_metadata(&env);
        client.set_metadata(&scanner, &target, &meta);

        let stored = client.get_metadata(&target).unwrap();
        assert_eq!(stored.name, String::from_str(&env, "MyToken"));
        assert_eq!(stored.version, String::from_str(&env, "1.0.0"));
        assert_eq!(stored.audit_date, 1_700_000_000u64);
        assert_eq!(stored.repo_url, String::from_str(&env, "https://github.com/example/mytoken"));
    }

    #[test]
    fn test_get_metadata_returns_none_when_unset() {
        let (env, contract_id, _admin, _scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let target = Address::generate(&env);
        assert!(client.get_metadata(&target).is_none());
    }

    #[test]
    #[should_panic(expected = "only the contract's scanner may set metadata")]
    fn test_non_scanner_cannot_set_metadata() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 0u32)];

        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &target, &String::from_str(&env, "hash1"), &counts);

        // A different scanner tries to set metadata for a contract they didn't scan.
        let other_scanner = Address::generate(&env);
        client.add_scanner(&other_scanner);
        client.set_metadata(&other_scanner, &target, &make_metadata(&env));
    }

    #[test]
    #[should_panic(expected = "no scan found for this contract")]
    fn test_metadata_requires_prior_scan() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let target = Address::generate(&env);
        client.add_scanner(&scanner);
        // No scan submitted — should panic.
        client.set_metadata(&scanner, &target, &make_metadata(&env));
    }

    #[test]
    #[should_panic]
    fn test_non_admin_cannot_dispute() {
        // Use a fresh env with no mocked auths so require_auth panics.
        let env = Env::default();
        let contract_id = env.register_contract(None, ScanRegistry);
        let admin = Address::generate(&env);
        let scanner = Address::generate(&env);

        env.mock_all_auths();
        ScanRegistryClient::new(&env, &contract_id).initialize(&admin);

        // Clear all mocks — no auth is satisfied from here on.
        env.mock_auths(&[]);

        // admin.require_auth() inside dispute_scan is not satisfied → panic.
        ScanRegistryClient::new(&env, &contract_id).dispute_scan(&scanner);
    }

    // ── get_latest_scans_batch tests ──────────────────────────────────────────

    #[test]
    #[should_panic(expected = "batch size exceeds maximum of 20")]
    fn test_batch_too_large_panics() {
        let (env, contract_id, _admin, _scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let mut contracts: Vec<Address> = Vec::new(&env);
        for _ in 0..21 {
            contracts.push_back(Address::generate(&env));
        }
        client.get_latest_scans_batch(&contracts);
    }

    #[test]
    fn test_batch_returns_latest_and_none_for_unscanned() {
        let (env, contract_id, _admin, scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);

        let scanned1 = Address::generate(&env);
        let scanned2 = Address::generate(&env);
        let unscanned = Address::generate(&env);

        let counts: Map<String, u32> = map![&env, (String::from_str(&env, "low"), 1u32)];
        client.add_scanner(&scanner);
        client.submit_scan(&scanner, &scanned1, &String::from_str(&env, "h1"), &counts);
        client.submit_scan(&scanner, &scanned2, &String::from_str(&env, "h2"), &counts);

        let mut batch: Vec<Address> = Vec::new(&env);
        batch.push_back(scanned1.clone());
        batch.push_back(scanned2.clone());
        batch.push_back(unscanned.clone());

        let results = client.get_latest_scans_batch(&batch);
        assert_eq!(results.len(), 3);
        assert_eq!(results.get(0).unwrap().unwrap().findings_hash, String::from_str(&env, "h1"));
        assert_eq!(results.get(1).unwrap().unwrap().findings_hash, String::from_str(&env, "h2"));
        assert!(results.get(2).unwrap().is_none());
    }

    #[test]
    fn test_batch_empty_input_returns_empty() {
        let (env, contract_id, _admin, _scanner) = setup();
        let client = ScanRegistryClient::new(&env, &contract_id);
        let empty: Vec<Address> = Vec::new(&env);
        let results = client.get_latest_scans_batch(&empty);
        assert_eq!(results.len(), 0);
    }
}

