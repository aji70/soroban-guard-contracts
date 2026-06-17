//! VULNERABLE: Audit Expiry Ignored
//!
//! An audit registry stores an `expiry_ledger` alongside each audit record,
//! but the read path returns the record unconditionally. Consumers that rely
//! on `get_active_audit` will treat stale attestations as current security
//! status long after the audit has expired.
//!
//! VULNERABILITY: `get_active_audit` never compares `expiry_ledger` against
//! `env.ledger().sequence()`, so expired audits are indistinguishable from
//! fresh ones.
//!
//! SECURE MIRROR: `secure::SecureAuditRegistry` returns `None` when
//! `ledger.sequence() > expiry_ledger`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct AuditRecord {
    pub auditor: Address,
    pub expiry_ledger: u32,
}

#[contracttype]
pub enum DataKey {
    Audit(u64), // contract_id -> AuditRecord
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableAuditRegistry;

#[contractimpl]
impl VulnerableAuditRegistry {
    /// Submit an audit for `contract_id` that expires at `expiry_ledger`.
    pub fn submit_audit(
        env: Env,
        auditor: Address,
        contract_id: u64,
        expiry_ledger: u32,
    ) {
        auditor.require_auth();
        let record = AuditRecord {
            auditor,
            expiry_ledger,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Audit(contract_id), &record);
    }

    /// VULNERABLE: returns the stored record without checking expiry.
    ///
    /// # Vulnerability
    /// `expiry_ledger` is stored but never compared to the current ledger
    /// sequence. Expired audits are returned as active. Impact: consumers
    /// treat stale attestations as current security status.
    pub fn get_active_audit(env: Env, contract_id: u64) -> Option<AuditRecord> {
        // ❌ BUG: missing expiry check — should return None when expired.
        env.storage()
            .persistent()
            .get(&DataKey::Audit(contract_id))
    }

    pub fn is_active(env: Env, contract_id: u64) -> bool {
        VulnerableAuditRegistry::get_active_audit(env, contract_id).is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    /// Demonstrates the vulnerability: expired audit is still returned as active.
    #[test]
    fn test_vulnerable_expired_audit_still_active() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAuditRegistry);
        let client = VulnerableAuditRegistryClient::new(&env, &id);

        let auditor = Address::generate(&env);
        let contract_id: u64 = 1;

        // Audit expires at ledger 10; submit at ledger 1.
        env.ledger().set_sequence_number(1);
        client.submit_audit(&auditor, &contract_id, &10);

        // Advance ledger past expiry.
        env.ledger().set_sequence_number(20);

        // ❌ Vulnerable: still reports active after expiry.
        assert!(client.is_active(&contract_id));
    }

    /// Boundary: audit that has not yet expired is correctly active.
    #[test]
    fn test_vulnerable_non_expired_audit_is_active() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAuditRegistry);
        let client = VulnerableAuditRegistryClient::new(&env, &id);

        let auditor = Address::generate(&env);
        let contract_id: u64 = 2;

        env.ledger().set_sequence_number(1);
        client.submit_audit(&auditor, &contract_id, &100);

        env.ledger().set_sequence_number(50);
        assert!(client.is_active(&contract_id));
    }

    /// Secure version: expired audit is reported as inactive.
    #[test]
    fn test_secure_expired_audit_is_inactive() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureAuditRegistry);
        let client = secure::SecureAuditRegistryClient::new(&env, &id);

        let auditor = Address::generate(&env);
        let contract_id: u64 = 3;

        env.ledger().set_sequence_number(1);
        client.submit_audit(&auditor, &contract_id, &10);

        // Advance past expiry.
        env.ledger().set_sequence_number(11);

        // ✅ Secure: expired audit is not active.
        assert!(!client.is_active(&contract_id));
    }

    /// Secure version: audit at exactly expiry ledger is still active.
    #[test]
    fn test_secure_audit_active_at_expiry_ledger() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureAuditRegistry);
        let client = secure::SecureAuditRegistryClient::new(&env, &id);

        let auditor = Address::generate(&env);
        let contract_id: u64 = 4;

        env.ledger().set_sequence_number(1);
        client.submit_audit(&auditor, &contract_id, &10);

        env.ledger().set_sequence_number(10);
        assert!(client.is_active(&contract_id));
    }
}
