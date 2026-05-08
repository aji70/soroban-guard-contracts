//! VULNERABLE: Redundant Admin Set
//!
//! `set_admin()` does not verify that `new_admin` differs from the current admin.
//! A no-op rotation emits a misleading `AdminChanged` event with identical addresses,
//! confusing off-chain monitors and wasting a ledger write.
//!
//! VULNERABILITY: missing `if new_admin == current { panic!(...) }` guard.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
}

#[contract]
pub struct AdminContract;

#[contractimpl]
impl AdminContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: no check that new_admin != current admin.
    /// A same-address call emits a misleading AdminChanged event.
    pub fn set_admin(env: Env, new_admin: Address) {
        let current: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        current.require_auth();

        // ❌ Missing: if new_admin == current { panic!("new_admin is already admin") }

        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.events()
            .publish((symbol_short!("AdmChng"),), (current, new_admin));
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Admin).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, AdminContractClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, AdminContract);
        let client = AdminContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin)
    }

    /// Demonstrates the bug: set_admin with the same address succeeds and emits an event.
    #[test]
    fn test_same_admin_set_succeeds_and_emits_event() {
        let (_env, client, admin) = setup();

        // BUG: should panic but doesn't — no identity check
        client.set_admin(&admin);

        assert_eq!(client.get_admin(), admin);
    }

    /// After the fix, passing the same address must panic.
    #[test]
    #[should_panic(expected = "new_admin is already admin")]
    fn test_same_admin_panics_after_fix() {
        let (_env, client, admin) = setup();

        // Documents expected fixed behaviour.
        // With the current vulnerable code this does NOT panic (bug).
        // Once the guard is added, this test will pass.
        client.set_admin(&admin);
    }

    /// A genuine rotation to a different address still works correctly.
    #[test]
    fn test_rotation_to_new_admin_works() {
        let (env, client, _old_admin) = setup();
        let new_admin = Address::generate(&env);

        client.set_admin(&new_admin);

        assert_eq!(client.get_admin(), new_admin);
    }
}
