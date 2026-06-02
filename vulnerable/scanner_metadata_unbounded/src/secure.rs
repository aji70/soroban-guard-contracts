//! SECURE: Scanner Registry with Metadata Size Enforcement
//!
//! FIXES APPLIED:
//! 1. `register_scanner` rejects empty metadata — callers must supply a meaningful value.
//! 2. `register_scanner` asserts `metadata.len() <= MAX_METADATA_LEN` before writing
//!    to storage, preventing unbounded storage growth and ledger rent inflation.

use super::{DataKey, MAX_METADATA_LEN};
use soroban_sdk::{contract, contractimpl, Address, Env, String};

#[contract]
pub struct SecureScannerRegistry;

#[contractimpl]
impl SecureScannerRegistry {
    /// SECURE: stores metadata only after validating its length.
    ///
    /// # Panics
    /// - If `metadata` is empty.
    /// - If `metadata.len()` exceeds `MAX_METADATA_LEN`.
    pub fn register_scanner(env: Env, scanner: Address, metadata: String) {
        scanner.require_auth();

        // ✅ FIX 1: Reject empty metadata.
        assert!(metadata.len() != 0, "metadata must not be empty");

        // ✅ FIX 2: Enforce maximum length to prevent storage bloat attacks.
        assert!(
            metadata.len() <= MAX_METADATA_LEN,
            "metadata exceeds maximum allowed length"
        );

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
}
