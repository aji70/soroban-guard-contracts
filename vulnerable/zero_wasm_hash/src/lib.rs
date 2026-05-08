//! VULNERABLE: Zero WASM Hash Accepted in Upgrade
//!
//! A contract whose `upgrade` function accepts a `BytesN<32>` WASM hash
//! without validating that it is non-zero. Passing a 32-byte zero hash
//! attempts to set the contract's WASM to a non-existent or invalid entry,
//! potentially bricking the contract permanently.
//!
//! An attacker with admin access can exploit this to irreversibly disable
//! the contract by supplying an all-zero hash.
//!
//! VULNERABILITY: No check that `new_wasm_hash != BytesN::from_array(&env, &[0u8; 32])`
//! before calling `env.deployer().update_current_contract_wasm()`.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct ZeroWasmHash;

#[contractimpl]
impl ZeroWasmHash {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: zero hash is accepted — can brick the contract.
    /// Missing: assert that new_wasm_hash is not all-zero bytes.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        // ❌ Missing: zero-hash guard
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

    fn setup() -> (Env, Address, ZeroWasmHashClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, ZeroWasmHash);
        let client = ZeroWasmHashClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, id, client)
    }

    /// Demonstrates the vulnerability: a zero BytesN<32> passes the
    /// validation layer without panicking. The contract does not reject it
    /// before forwarding to update_current_contract_wasm.
    ///
    /// Note: update_current_contract_wasm itself will fail at the host level
    /// because the hash doesn't exist in the ledger, but the contract's own
    /// guard never fires — that is the bug being demonstrated.
    #[test]
    fn test_zero_hash_not_rejected_by_contract() {
        let (env, _id, client) = setup();
        let zero_hash = BytesN::from_array(&env, &[0u8; 32]);

        // Catch the host-level panic from update_current_contract_wasm, but
        // confirm it is NOT our validation panic — the contract has no guard.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.upgrade(&zero_hash);
        }));

        // The call panics at the host/deployer level, not at a contract guard.
        // A secure contract would panic with "wasm hash must not be zero" before
        // ever reaching update_current_contract_wasm.
        if let Err(e) = result {
            let msg = e
                .downcast_ref::<std::string::String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(
                !msg.contains("wasm hash must not be zero"),
                "vulnerable contract must not have the zero-hash guard, but it does"
            );
        }
        // If it didn't panic at all, the zero hash was silently accepted — also demonstrates the bug.
    }

    /// Secure version rejects a zero hash before reaching update_current_contract_wasm.
    #[test]
    #[should_panic(expected = "wasm hash must not be zero")]
    fn test_secure_rejects_zero_hash() {
        use crate::secure::SecureUpgradeClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureUpgrade);
        let client = SecureUpgradeClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let zero_hash = BytesN::from_array(&env, &[0u8; 32]);
        client.upgrade(&zero_hash);
    }

    /// Secure version allows a non-zero hash to pass the guard and proceed
    /// to the upgrade call (host may still fail if hash isn't on-ledger,
    /// but the contract-level validation passes).
    #[test]
    fn test_secure_nonzero_hash_passes_guard() {
        use crate::secure::SecureUpgradeClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureUpgrade);
        let client = SecureUpgradeClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        // A non-zero hash — all 0xAB bytes.
        let valid_hash = BytesN::from_array(&env, &[0xABu8; 32]);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.upgrade(&valid_hash);
        }));

        // The contract guard passes; any panic here comes from the host
        // (hash not on ledger), not from our zero-hash check.
        if let Err(e) = result {
            let msg = e
                .downcast_ref::<std::string::String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(
                !msg.contains("wasm hash must not be zero"),
                "non-zero hash must not be rejected by the guard"
            );
        }
    }

    /// Normal admin operations are unaffected by the guard.
    #[test]
    fn test_get_admin_works() {
        let (env, _id, client) = setup();
        let _ = client.get_admin();
    }
}
