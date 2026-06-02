//! VULNERABLE: Scanner Metadata Stored Without Size Limit
//!
//! A scanner registry where `register_scanner` persists arbitrary caller-supplied
//! metadata strings with no length cap. An attacker can submit very large payloads,
//! bloating persistent storage and increasing ledger rent costs for all readers.
//!
//! VULNERABILITY: Caller-supplied `metadata` is written to persistent storage
//! without any length validation — missing `assert!(metadata.len() <= MAX_METADATA_LEN)`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

pub mod secure;

/// Maximum allowed byte length for scanner metadata (used by the secure implementation).
pub const MAX_METADATA_LEN: u32 = 256;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Metadata(Address),
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct ScannerRegistry;

#[contractimpl]
impl ScannerRegistry {
    /// VULNERABLE: stores caller-supplied `metadata` for `scanner` with no size cap.
    ///
    /// # Vulnerability
    /// Missing `assert!(metadata.len() <= MAX_METADATA_LEN)`.
    /// Impact: unbounded storage growth — attackers can persist arbitrarily large
    /// strings, inflating ledger rent and exceeding practical read limits.
    pub fn register_scanner(env: Env, scanner: Address, metadata: String) {
        scanner.require_auth();
        // ❌ Missing: assert!(metadata.len() <= MAX_METADATA_LEN, "metadata too large");
        env.storage()
            .persistent()
            .set(&DataKey::Metadata(scanner), &metadata);
    }

    /// Returns the stored metadata for `scanner`, or an empty string if not registered.
    pub fn get_metadata(env: Env, scanner: Address) -> String {
        env.storage()
            .persistent()
            .get(&DataKey::Metadata(scanner))
            .unwrap_or(String::from_str(&env, ""))
    }

    /// Fixture entry matching the issue's vulnerable pattern signature.
    ///
    /// # Vulnerability
    /// BUG: caller-supplied metadata is persisted without a length cap.
    /// The unsafe path is reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        // BUG: `amount` is used as a repeat count — metadata grows proportionally
        // with no upper bound enforced before the write.
        let metadata = if amount > 0 {
            String::from_str(&env, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        } else {
            String::from_str(&env, "x")
        };
        // ❌ No size check before persisting.
        env.storage()
            .persistent()
            .set(&DataKey::Metadata(actor), &metadata);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureScannerRegistryClient;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, ScannerRegistry);
        (env, id)
    }

    // ── Vulnerable path ───────────────────────────────────────────────────────

    /// Demonstrates the vulnerability: a large metadata string is accepted and stored.
    /// Uses budget().reset_unlimited() so the test is not blocked by instruction limits.
    #[test]
    fn test_vulnerable_stores_large_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let id = env.register_contract(None, ScannerRegistry);
        let client = ScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        // 512-char string — well beyond MAX_METADATA_LEN (256).
        // ❌ Vulnerable path: no rejection — oversized metadata is persisted.
        let big = String::from_str(
            &env,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
             AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 512 A's
        );
        client.register_scanner(&scanner, &big);

        let stored = client.get_metadata(&scanner);
        assert!(stored.len() > MAX_METADATA_LEN);
    }

    /// Boundary condition: a string of exactly MAX_METADATA_LEN + 1 bytes is accepted
    /// by the vulnerable contract but must be rejected by the secure one.
    #[test]
    fn test_vulnerable_accepts_boundary_violation() {
        let (env, id) = setup();
        let client = ScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        // 257-char string: one byte over the limit the secure version enforces.
        let over_limit = String::from_str(
            &env,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             X", // 4*64 + 1 = 257 X's
        );

        // ❌ Vulnerable contract stores it without complaint.
        client.register_scanner(&scanner, &over_limit);
        assert!(client.get_metadata(&scanner).len() > MAX_METADATA_LEN);
    }

    // ── Secure path ───────────────────────────────────────────────────────────

    /// Secure implementation rejects metadata that exceeds MAX_METADATA_LEN.
    #[test]
    #[should_panic]
    fn test_secure_rejects_oversized_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureScannerRegistry);
        let client = SecureScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        let over_limit = String::from_str(
            &env,
            "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\
             X", // 4*64 + 1 = 257 X's
        );

        // ✅ Secure path: panics because metadata exceeds the cap.
        client.register_scanner(&scanner, &over_limit);
    }

    /// Secure implementation accepts metadata within the allowed length.
    #[test]
    fn test_secure_accepts_valid_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureScannerRegistry);
        let client = SecureScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        let valid = String::from_str(&env, "scanner-v1.0.0");
        client.register_scanner(&scanner, &valid);
        assert_eq!(client.get_metadata(&scanner).len(), 14);
    }

    /// Secure implementation rejects empty metadata.
    #[test]
    #[should_panic]
    fn test_secure_rejects_empty_metadata() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureScannerRegistry);
        let client = SecureScannerRegistryClient::new(&env, &id);
        let scanner = Address::generate(&env);

        // ✅ Secure path: panics because metadata is empty.
        client.register_scanner(&scanner, &String::from_str(&env, ""));
    }
}
