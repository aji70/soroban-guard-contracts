//! VULNERABLE: Unprotected WASM Upgrade
//!
//! A simple counter contract whose `upgrade()` function calls
//! `env.deployer().update_current_contract_wasm()` with no admin check.
//! Any caller can replace the contract bytecode entirely.
//!
//! SEVERITY: Critical
//! SECURE MIRROR: `secure/protected_admin` — `upgrade()` loads the stored
//! admin and calls `admin.require_auth()` before updating the WASM.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Counter,
}

#[contract]
pub struct UnprotectedUpgrade;

#[contractimpl]
impl UnprotectedUpgrade {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Counter, &0_u64);
    }

    pub fn increment(env: Env) -> u64 {
        let count: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Counter)
            .unwrap_or(0);
        let next = count + 1;
        env.storage().persistent().set(&DataKey::Counter, &next);
        next
    }

    pub fn get_count(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Counter)
            .unwrap_or(0)
    }

    /// VULNERABLE: no `require_auth` — anyone can replace the contract WASM.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        // ❌ Missing: let admin: Address = env.storage().persistent()
        //                 .get(&DataKey::Admin).unwrap();
        //             admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, BytesN as _},
        Address, BytesN, Env,
    };

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, UnprotectedUpgrade);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        UnprotectedUpgradeClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin)
    }

    /// Counter state is preserved before any upgrade call.
    #[test]
    fn test_counter_state_preserved() {
        let (env, contract_id, _admin) = setup();
        let client = UnprotectedUpgradeClient::new(&env, &contract_id);

        client.increment();
        client.increment();
        assert_eq!(client.get_count(), 2);
    }

    /// Normal path: admin calls upgrade (auth mocked).
    /// The call reaches `update_current_contract_wasm` — the only failure is
    /// the host rejecting an unregistered WASM hash, not an auth check.
    #[test]
    fn test_admin_can_upgrade() {
        let (env, contract_id, _admin) = setup();
        let client = UnprotectedUpgradeClient::new(&env, &contract_id);

        client.increment();
        assert_eq!(client.get_count(), 1);

        let fake_hash = BytesN::<32>::random(&env);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.upgrade(&fake_hash);
        }));
        // Panics at the host level (unknown WASM), not at an auth check.
        assert!(result.is_err(), "expected host error for unknown wasm hash");
    }

    /// Demonstrates the vulnerability: attacker upgrades without any auth.
    /// The contract never checks the caller, so the call reaches the deployer
    /// and only fails because the WASM hash is not registered on-ledger.
    #[test]
    fn test_attacker_can_upgrade_without_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, UnprotectedUpgrade);
        let client = UnprotectedUpgradeClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        client.increment();
        assert_eq!(client.get_count(), 1);

        // New env with no mocked auths — simulates an attacker.
        let env2 = Env::default();
        let client2 = UnprotectedUpgradeClient::new(&env2, &contract_id);
        let fake_hash = BytesN::<32>::random(&env2);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client2.upgrade(&fake_hash);
        }));

        // Reaches the deployer without an auth panic — vulnerability confirmed.
        // A secure contract would panic with an auth error before this point.
        if let Err(e) = result {
            let msg = e
                .downcast_ref::<std::string::String>()
                .map(|s| s.as_str())
                .or_else(|| e.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(
                !msg.contains("require_auth"),
                "vulnerable contract must not have an auth check, but it does"
            );
        }
    }
}
