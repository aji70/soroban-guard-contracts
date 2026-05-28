//! SECURE mirror: slashing requires a finalized evidence record.
//!
//! Fixes the vulnerability in `VulnerableSlash`:
//! - ✅ `slash` checks that a finalized evidence record exists for the scanner
//!   before moving any stake.
//! - ✅ Evidence records are submitted and finalized by the admin, creating an
//!   auditable trail before any stake is confiscated.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Vec};

// symbol_short is used in event publishing inside register_scanner and slash.

/// Status of an evidence record.
#[contracttype]
#[derive(Clone, PartialEq)]
pub enum EvidenceStatus {
    Pending,
    Finalized,
}

/// An evidence record linking a scanner to a report.
#[contracttype]
#[derive(Clone)]
pub struct EvidenceRecord {
    pub scanner: Address,
    pub report_id: u64,
    pub status: EvidenceStatus,
}

/// Additional storage keys used only by the secure contract.
#[contracttype]
pub enum SecureDataKey {
    /// Evidence record keyed by report ID.
    Evidence(u64),
    /// Vec<u64> index of all submitted report IDs.
    EvidenceIds,
}

#[contract]
pub struct SecureSlash;

#[contractimpl]
impl SecureSlash {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn register_scanner(env: Env, scanner: Address, stake: i128) {
        scanner.require_auth();
        assert!(stake > 0, "stake must be positive");
        env.storage()
            .persistent()
            .set(&DataKey::Stake(scanner.clone()), &stake);
        env.events()
            .publish((symbol_short!("scanner"), symbol_short!("staked")), (scanner, stake));
    }

    /// Admin submits an evidence record for a scanner (status: Pending).
    /// The report ID is tracked in an index Vec so `slash` can scan it.
    pub fn submit_evidence(env: Env, scanner: Address, report_id: u64) {
        Self::require_admin(&env);
        let record = EvidenceRecord {
            scanner,
            report_id,
            status: EvidenceStatus::Pending,
        };
        env.storage()
            .persistent()
            .set(&SecureDataKey::Evidence(report_id), &record);

        // ✅ Track the report ID so slash can find it.
        let mut ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&SecureDataKey::EvidenceIds)
            .unwrap_or(Vec::new(&env));
        ids.push_back(report_id);
        env.storage()
            .persistent()
            .set(&SecureDataKey::EvidenceIds, &ids);
    }

    /// Admin finalizes a pending evidence record, making it eligible for slashing.
    pub fn finalize_evidence(env: Env, report_id: u64) {
        Self::require_admin(&env);
        let mut record: EvidenceRecord = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Evidence(report_id))
            .expect("evidence not found");
        record.status = EvidenceStatus::Finalized;
        env.storage()
            .persistent()
            .set(&SecureDataKey::Evidence(report_id), &record);
    }

    /// ✅ Slash only proceeds when a finalized evidence record exists for the scanner.
    pub fn slash(env: Env, scanner: Address, amount: i128) {
        Self::require_admin(&env);

        // ✅ Require a finalized evidence record before moving stake.
        if !Self::has_finalized_evidence(&env, &scanner) {
            panic!("no finalized evidence");
        }

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

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }

    /// Returns `true` if any evidence record for `scanner` has status Finalized.
    fn has_finalized_evidence(env: &Env, scanner: &Address) -> bool {
        let ids: Vec<u64> = env
            .storage()
            .persistent()
            .get(&SecureDataKey::EvidenceIds)
            .unwrap_or(Vec::new(env));

        for id in ids.iter() {
            if let Some(record) = env
                .storage()
                .persistent()
                .get::<SecureDataKey, EvidenceRecord>(&SecureDataKey::Evidence(id))
            {
                if record.scanner == *scanner && record.status == EvidenceStatus::Finalized {
                    return true;
                }
            }
        }
        false
    }
}
