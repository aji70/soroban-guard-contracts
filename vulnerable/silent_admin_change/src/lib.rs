//! VULNERABLE: Silent Admin Change — No Event on Admin Transfer
//!
//! The `set_admin` function updates the admin address in persistent storage
//! but never calls `env.events().publish()`. Off-chain monitors, dashboards,
//! and audit tools have no way to detect admin changes without polling storage
//! on every ledger. A malicious or compromised admin can silently transfer
//! control to an attacker-controlled address with no on-chain trace.
//!
//! VULNERABILITY: Missing `env.events().publish()` after the storage write in `set_admin`.

#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

const ADMIN_KEY: &str = "admin";

#[contract]
pub struct SilentAdminContract;

#[contractimpl]
impl SilentAdminContract {
    /// Initialise the contract with an admin. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&ADMIN_KEY) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&ADMIN_KEY, &admin);
    }

    /// VULNERABLE: updates admin in storage but emits no event.
    /// Off-chain monitors cannot detect this privilege escalation.
    ///
    /// # Vulnerability
    /// Missing `env.events().publish(...)` after the storage write.
    /// Impact: silent privilege escalation — admin change is invisible to off-chain tools.
    pub fn set_admin(env: Env, new_admin: Address) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&ADMIN_KEY)
            .expect("not initialized");
        current.require_auth();

        // ❌ BUG: no event emitted — admin change is invisible to off-chain monitors
        env.storage().persistent().set(&ADMIN_KEY, &new_admin);
    }

    /// Returns the current admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&ADMIN_KEY)
            .expect("not initialized")
    }
}

pub mod secure {
    use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

    const ADMIN_KEY: &str = "admin";

    #[contract]
    pub struct SecureAdminContract;

    #[contractimpl]
    impl SecureAdminContract {
        pub fn initialize(env: Env, admin: Address) {
            if env.storage().persistent().has(&ADMIN_KEY) {
                panic!("already initialized");
            }
            env.storage().persistent().set(&ADMIN_KEY, &admin);
        }

        /// SECURE: emits an AdminChg event after updating the admin.
        pub fn set_admin(env: Env, new_admin: Address) {
            let old_admin: Address = env
                .storage()
                .persistent()
                .get(&ADMIN_KEY)
                .expect("not initialized");
            old_admin.require_auth();

            env.storage().persistent().set(&ADMIN_KEY, &new_admin);

            // ✅ Emit event so off-chain monitors can detect the change
            env.events().publish(
                (symbol_short!("AdminChg"),),
                (old_admin, new_admin),
            );
        }

        pub fn get_admin(env: Env) -> Address {
            env.storage()
                .persistent()
                .get(&ADMIN_KEY)
                .expect("not initialized")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env,
    };

    fn setup() -> (Env, SilentAdminContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SilentAdminContract);
        let client = SilentAdminContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin)
    }

    /// Demonstrates the bug: set_admin produces zero events.
    #[test]
    fn test_vulnerable_set_admin_emits_no_events() {
        let (env, client, _old_admin) = setup();
        let new_admin = Address::generate(&env);

        client.set_admin(&new_admin);

        let events = env.events().all();
        assert_eq!(
            events.len(),
            0,
            "vulnerable set_admin must emit zero events — this is the bug"
        );
        assert_eq!(client.get_admin(), new_admin);
    }

    /// After the fix (secure module), set_admin emits exactly one AdminChg event
    /// with the correct old and new admin addresses.
    #[test]
    fn test_secure_set_admin_emits_admin_chg_event() {
        use crate::secure::SecureAdminContract;
        use soroban_sdk::{symbol_short, IntoVal, Val, Vec, TryFromVal};

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureAdminContract);
        let client = secure::SecureAdminContractClient::new(&env, &id);

        let old_admin = Address::generate(&env);
        let new_admin = Address::generate(&env);
        client.initialize(&old_admin);

        client.set_admin(&new_admin);

        let events = env.events().all();
        assert_eq!(events.len(), 1, "expected exactly one AdminChg event");

        let (_, topics, data) = events.last().unwrap();

        // Verify topic is ("AdminChg",)
        let topic_vec = Vec::<Val>::try_from_val(&env, &topics).unwrap();
        let topic_sym = soroban_sdk::Symbol::try_from_val(&env, &topic_vec.get(0).unwrap()).unwrap();
        assert_eq!(topic_sym, symbol_short!("AdminChg"));

        // Verify data contains (old_admin, new_admin)
        let data_vec = Vec::<Val>::try_from_val(&env, &data).unwrap();
        let emitted_old = Address::try_from_val(&env, &data_vec.get(0).unwrap()).unwrap();
        let emitted_new = Address::try_from_val(&env, &data_vec.get(1).unwrap()).unwrap();
        assert_eq!(emitted_old, old_admin);
        assert_eq!(emitted_new, new_admin);
    }

    /// Event must NOT be emitted if set_admin panics due to missing auth.
    #[test]
    fn test_secure_no_event_on_auth_failure() {
        extern crate std;
        use crate::secure::SecureAdminContract;

        let env = Env::default();
        let id = env.register_contract(None, SecureAdminContract);
        let client = secure::SecureAdminContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        // Initialize without mocking auths so set_admin will fail auth
        env.mock_all_auths();
        client.initialize(&admin);

        // Drop mock_all_auths — no auth provided for the next call
        let env2 = Env::default();
        let id2 = env2.register_contract(None, SecureAdminContract);
        let client2 = secure::SecureAdminContractClient::new(&env2, &id2);
        env2.mock_all_auths();
        client2.initialize(&admin);

        // Now call without any auth mock — should panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client2.set_admin(&attacker);
        }));

        assert!(result.is_err(), "set_admin must panic without valid auth");

        // No events should have been emitted
        let events = env2.events().all();
        assert_eq!(events.len(), 0, "no event must be emitted on auth failure");
    }
}
