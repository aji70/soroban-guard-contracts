//! VULNERABLE: TTL Bump Index Only
//!
//! A registry that maintains two paired storage keys per account: an index
//! entry (used for enumeration) and a record entry (the actual data). When
//! refreshing TTL the contract only bumps the index key, leaving the record
//! key to expire on its own schedule.
//!
//! After enough ledgers the index entry is still alive but the record entry
//! has expired. Any code that follows the index to read the record will either
//! panic (in the test harness) or return stale/missing data on a live network.
//!
//! VULNERABILITY: `refresh` calls `extend_ttl` on `IndexEntry(account)` but
//! not on `RecordEntry(account)`, causing the two keys to diverge in TTL.
//!
//! Severity: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

pub mod secure;

// ── TTL constants ─────────────────────────────────────────────────────────────

/// Minimum remaining TTL before we extend.
pub const TTL_THRESHOLD: u32 = 10;
/// Target TTL after extension.
pub const TTL_EXTEND_TO: u32 = 100;

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct AccountRecord {
    pub owner: Address,
    pub data: String,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Index entry — presence signals the account is registered.
    IndexEntry(Address),
    /// The actual record data for the account.
    RecordEntry(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableRegistry;

#[contractimpl]
impl VulnerableRegistry {
    /// Register an account with some associated data string.
    pub fn register(env: Env, account: Address, data: String) {
        account.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::IndexEntry(account.clone()), &true);
        env.storage().persistent().set(
            &DataKey::RecordEntry(account.clone()),
            &AccountRecord {
                owner: account.clone(),
                data,
            },
        );
        // Both keys start with the same default TTL — no explicit extend needed here.
    }

    /// VULNERABLE: refreshes TTL for the index entry only.
    ///
    /// The record entry is left to expire independently. After `TTL_EXTEND_TO`
    /// ledgers the index still exists but the record is gone.
    ///
    /// # Vulnerability
    /// Missing: `env.storage().persistent().extend_ttl(&DataKey::RecordEntry(account.clone()), TTL_THRESHOLD, TTL_EXTEND_TO);`
    pub fn refresh(env: Env, account: Address) {
        // ✅ Index TTL is refreshed.
        env.storage().persistent().extend_ttl(
            &DataKey::IndexEntry(account.clone()),
            TTL_THRESHOLD,
            TTL_EXTEND_TO,
        );
        // ❌ Missing: extend_ttl for RecordEntry — record will expire while index survives.
    }

    /// Look up the record for `account` by following the index.
    ///
    /// Panics if the index entry exists but the record has expired.
    pub fn get_record(env: Env, account: Address) -> AccountRecord {
        let indexed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::IndexEntry(account.clone()))
            .unwrap_or(false);
        if !indexed {
            panic!("account not registered");
        }
        // If the record entry has expired this will panic in the test harness
        // (or return missing data on a live network).
        env.storage()
            .persistent()
            .get(&DataKey::RecordEntry(account))
            .expect("record expired: index points to missing data")
    }

    /// Returns `true` if the index entry for `account` is still alive.
    pub fn is_indexed(env: Env, account: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::IndexEntry(account))
            .unwrap_or(false)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{storage::Persistent as _, Address as _, Ledger as _},
        Address, Env, String,
    };

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.ledger().set_min_persistent_entry_ttl(5);
        env.ledger().set_max_entry_ttl(200);
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableRegistry);
        let account = Address::generate(&env);
        (env, contract_id, account)
    }

    fn pin_instance(env: &Env, contract_id: &Address) {
        env.as_contract(contract_id, || {
            let max = env.storage().max_ttl();
            env.storage().instance().extend_ttl(max, max);
        });
    }

    /// Normal registration and lookup works before any TTL expiry.
    #[test]
    fn test_register_and_get_record_works() {
        let (env, contract_id, account) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);

        client.register(&account, &String::from_str(&env, "payload"));
        let rec = client.get_record(&account);
        assert_eq!(rec.data, String::from_str(&env, "payload"));
    }

    /// DEMONSTRATES VULNERABILITY: after refresh the index survives but the
    /// record expires, causing `get_record` to panic.
    #[test]
    #[should_panic(expected = "record expired")]
    fn test_index_alive_but_record_expired() {
        let (env, contract_id, account) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);

        client.register(&account, &String::from_str(&env, "data"));
        pin_instance(&env, &contract_id);

        // Refresh only bumps the index TTL.
        client.refresh(&account);

        // Verify: index TTL was extended, record TTL was NOT.
        env.as_contract(&contract_id, || {
            let idx_ttl = env
                .storage()
                .persistent()
                .get_ttl(&DataKey::IndexEntry(account.clone()));
            let rec_ttl = env
                .storage()
                .persistent()
                .get_ttl(&DataKey::RecordEntry(account.clone()));
            // Index was bumped to TTL_EXTEND_TO; record still has its original short TTL.
            assert!(idx_ttl > rec_ttl, "index TTL should exceed record TTL after vulnerable refresh");
        });

        // Advance ledgers past the record's original TTL so it expires.
        env.ledger().set_sequence_number(10);

        // Index is still alive — is_indexed returns true.
        assert!(client.is_indexed(&account));

        // But following the index to the record panics — inconsistent state.
        client.get_record(&account);
    }

    /// Boundary: calling get_record on an unregistered account panics cleanly.
    #[test]
    #[should_panic(expected = "account not registered")]
    fn test_get_record_unregistered_panics() {
        let (env, contract_id, account) = setup();
        let client = VulnerableRegistryClient::new(&env, &contract_id);
        client.get_record(&account);
    }

    /// Secure version refreshes both keys so the record never expires while
    /// the index is alive.
    #[test]
    fn test_secure_refresh_keeps_record_alive() {
        use crate::secure::SecureRegistryClient;

        let env = Env::default();
        env.ledger().set_min_persistent_entry_ttl(5);
        env.ledger().set_max_entry_ttl(200);
        env.mock_all_auths();

        let contract_id = env.register_contract(None, secure::SecureRegistry);
        let client = SecureRegistryClient::new(&env, &contract_id);
        let account = Address::generate(&env);

        client.register(&account, &String::from_str(&env, "data"));
        pin_instance(&env, &contract_id);

        client.refresh(&account);

        // Advance ledgers past the original short TTL.
        env.ledger().set_sequence_number(10);

        // Both keys were bumped — record is still readable.
        let rec = client.get_record(&account);
        assert_eq!(rec.data, String::from_str(&env, "data"));
    }
}
