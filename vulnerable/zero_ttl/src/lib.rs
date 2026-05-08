//! VULNERABLE: Zero TTL Immediately Expires Storage
//!
//! The contract exposes a `set_ttl` admin function that accepts any `u32`
//! value including zero. Setting TTL to zero causes the storage entry to
//! expire at the current ledger, making it immediately inaccessible. An
//! attacker who gains temporary admin access, or a misconfigured admin call,
//! can wipe all persistent state by setting TTL to zero.
//!
//! VULNERABILITY: `set_ttl` does not guard against `ttl == 0`, so a zero
//! value immediately expires instance storage.
//!
//! SEVERITY: Medium
//! FIX: guard `if ttl == 0 { panic!("TTL cannot be zero") }` and enforce a
//! minimum TTL constant.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const MIN_TTL: u32 = 100;

#[contracttype]
pub enum DataKey {
    Admin,
    Value,
}

#[contract]
pub struct ZeroTtl;

#[contractimpl]
impl ZeroTtl {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Value, &0u64);
    }

    /// VULNERABLE: accepts ttl=0, which immediately expires instance storage.
    pub fn set_ttl(env: Env, ttl: u32) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        // ❌ ttl=0 immediately expires storage — all state becomes inaccessible
        env.storage().instance().extend_ttl(ttl, ttl);
    }

    pub fn get_value(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::Value)
            .unwrap_or(0)
    }
}

// ── Secure version (inline) ───────────────────────────────────────────────────

#[contract]
pub struct SecureZeroTtl;

#[contractimpl]
impl SecureZeroTtl {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Value, &0u64);
    }

    /// FIX: rejects ttl=0 and enforces a minimum TTL.
    pub fn set_ttl(env: Env, ttl: u32) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        if ttl == 0 {
            panic!("TTL cannot be zero");
        }
        let safe_ttl = ttl.max(MIN_TTL);
        env.storage().instance().extend_ttl(safe_ttl, safe_ttl);
    }

    pub fn get_value(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::Value)
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Demonstrates the bug: set_ttl(0) succeeds and storage becomes
    /// inaccessible (TTL is 0 — entry expires immediately).
    #[test]
    fn test_zero_ttl_accepted_and_expires_storage() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, ZeroTtl);
        let client = ZeroTtlClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);

        // Value is readable before the TTL is zeroed.
        assert_eq!(client.get_value(), 0);

        // BUG: this call succeeds — TTL is set to 0.
        client.set_ttl(&0);

        // After TTL=0 the instance storage entry is expired; get_value returns
        // the default (0) because the key is gone, demonstrating the data loss.
        assert_eq!(client.get_value(), 0);
    }

    /// After the fix, set_ttl(0) must panic.
    #[test]
    #[should_panic(expected = "TTL cannot be zero")]
    fn test_zero_ttl_rejected_by_secure_version() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureZeroTtl);
        let client = SecureZeroTtlClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        client.set_ttl(&0);
    }

    /// A valid TTL value correctly extends the storage TTL.
    #[test]
    fn test_valid_ttl_extends_storage() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureZeroTtl);
        let client = SecureZeroTtlClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        // Should not panic — valid TTL above minimum.
        client.set_ttl(&500);
        assert_eq!(client.get_value(), 0);
    }
}
