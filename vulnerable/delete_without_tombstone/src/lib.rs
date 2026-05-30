//! VULNERABLE: Delete Without Tombstone — Stale-Approval Replay
//!
//! A registry stores entries approved by an off-chain signature (SHA-256 of
//! the payload). When an entry is deleted the storage key is simply removed,
//! erasing all nonce history. An attacker can then replay the original
//! approval to recreate the deleted entry.
//!
//! VULNERABILITY: `delete_entry()` calls `env.storage().persistent().remove()`
//! which wipes the nonce record. A subsequent `approve_entry()` with the same
//! old signature succeeds because the contract sees no prior usage.
//!
//! SECURE MIRROR: `secure::SecureRegistry` replaces live entries with a
//! tombstone that preserves the highest nonce seen. Any approval whose nonce
//! is ≤ the tombstone nonce is rejected.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Bytes, BytesN, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Simulated approval signature: SHA-256 of the payload.
pub fn verify_approval(env: &Env, payload: &Bytes, sig: &BytesN<32>) {
    let expected: BytesN<32> = env.crypto().sha256(payload).into();
    if expected != *sig {
        panic!("invalid approval");
    }
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Live entry: stores the nonce (u32) used when it was approved.
    Entry(Bytes),
    /// Tombstone: stores the nonce at deletion time (secure contract only).
    Tombstone(Bytes),
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableRegistry;

#[contractimpl]
impl VulnerableRegistry {
    /// Approve (create/update) an entry.
    /// The signature is the SHA-256 of `payload ++ nonce_bytes`.
    /// VULNERABLE: does not check tombstone — deleted entries can be recreated.
    pub fn approve_entry(env: Env, payload: Bytes, nonce: u32, sig: BytesN<32>) {
        // Build the signed message: payload bytes followed by nonce as 4 LE bytes.
        let mut msg = payload.clone();
        let nb = nonce.to_le_bytes();
        msg.extend_from_slice(&nb);
        verify_approval(&env, &msg, &sig);

        // ❌ No tombstone check — stale approvals recreate deleted entries.
        env.storage()
            .persistent()
            .set(&DataKey::Entry(payload.clone()), &nonce);

        env.events()
            .publish((symbol_short!("approved"),), payload);
    }

    /// Delete an entry entirely — erases nonce history.
    /// VULNERABLE: removes the key, so old approvals become valid again.
    pub fn delete_entry(env: Env, payload: Bytes) {
        // ❌ Hard delete: nonce history is gone.
        env.storage()
            .persistent()
            .remove(&DataKey::Entry(payload.clone()));

        env.events()
            .publish((symbol_short!("deleted"),), payload);
    }

    /// Returns the stored nonce for an entry, or None if absent.
    pub fn get_entry(env: Env, payload: Bytes) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::Entry(payload))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Bytes, Env};

    fn make_sig(env: &Env, payload: &Bytes, nonce: u32) -> BytesN<32> {
        let mut msg = payload.clone();
        msg.extend_from_slice(&nonce.to_le_bytes());
        env.crypto().sha256(&msg).into()
    }

    // -----------------------------------------------------------------------
    // Vulnerable contract tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_vulnerable_approve_succeeds() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableRegistry);
        let client = VulnerableRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig = make_sig(&env, &key, 1);
        client.approve_entry(&key, &1, &sig);
        assert_eq!(client.get_entry(&key), Some(1));
    }

    #[test]
    fn test_vulnerable_delete_removes_entry() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableRegistry);
        let client = VulnerableRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig = make_sig(&env, &key, 1);
        client.approve_entry(&key, &1, &sig);
        client.delete_entry(&key);
        assert_eq!(client.get_entry(&key), None);
    }

    /// Demonstrates the vulnerability: after deletion the old approval can
    /// recreate the entry because no tombstone was left behind.
    #[test]
    fn test_vulnerable_stale_approval_recreates_entry() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableRegistry);
        let client = VulnerableRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig = make_sig(&env, &key, 1);

        // Approve, then delete.
        client.approve_entry(&key, &1, &sig);
        client.delete_entry(&key);
        assert_eq!(client.get_entry(&key), None);

        // Replay the original approval — succeeds on the vulnerable contract.
        client.approve_entry(&key, &1, &sig);
        // Entry is back — unsafe state restored from stale approval.
        assert_eq!(client.get_entry(&key), Some(1));
    }

    // -----------------------------------------------------------------------
    // Secure contract tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_secure_approve_succeeds() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = secure::SecureRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig = make_sig(&env, &key, 1);
        client.approve_entry(&key, &1, &sig);
        assert_eq!(client.get_entry(&key), Some(1));
    }

    #[test]
    fn test_secure_delete_leaves_tombstone() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = secure::SecureRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig = make_sig(&env, &key, 1);
        client.approve_entry(&key, &1, &sig);
        client.delete_entry(&key);
        // Live entry is gone.
        assert_eq!(client.get_entry(&key), None);
    }

    /// Boundary: stale approval (nonce ≤ tombstone nonce) must be rejected.
    #[test]
    #[should_panic(expected = "stale approval")]
    fn test_secure_stale_approval_rejected() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = secure::SecureRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig = make_sig(&env, &key, 1);

        client.approve_entry(&key, &1, &sig);
        client.delete_entry(&key);

        // Replay old nonce=1 — must panic.
        client.approve_entry(&key, &1, &sig);
    }

    /// A fresh approval with a higher nonce is accepted after deletion.
    #[test]
    fn test_secure_fresh_approval_after_delete_succeeds() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureRegistry);
        let client = secure::SecureRegistryClient::new(&env, &id);

        let key = Bytes::from_slice(&env, b"user:alice");
        let sig1 = make_sig(&env, &key, 1);
        client.approve_entry(&key, &1, &sig1);
        client.delete_entry(&key);

        // New approval with nonce=2 — accepted.
        let sig2 = make_sig(&env, &key, 2);
        client.approve_entry(&key, &2, &sig2);
        assert_eq!(client.get_entry(&key), Some(2));
    }
}
