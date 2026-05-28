//! VULNERABLE: Initialization Defaults Admin to Current Contract Address
//!
//! If no admin is supplied, the contract stores its own address as admin. No
//! external signer can satisfy `require_auth()` for that address, so privileged
//! functions are permanently locked.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Value,
}

#[contract]
pub struct CurrentContractAdmin;

#[contractimpl]
impl CurrentContractAdmin {
    pub fn initialize(env: Env, admin: Option<Address>) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        let stored = admin.unwrap_or_else(|| env.current_contract_address());
        env.storage().persistent().set(&DataKey::Admin, &stored);
    }

    pub fn admin_action(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Value, &1u32);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    pub fn value(env: Env) -> u32 {
        env.storage().persistent().get(&DataKey::Value).unwrap_or(0)
    }

    pub fn vulnerable_entry(env: Env, _actor: Address, _amount: i128) {
        Self::initialize(env, None);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, CurrentContractAdminClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, CurrentContractAdmin);
        let client = CurrentContractAdminClient::new(&env, &id);
        (env, id, client)
    }

    #[test]
    fn vulnerable_path() {
        let (_env, id, client) = setup();
        client.initialize(&None);
        assert_eq!(client.get_admin(), id);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.admin_action();
        }));
        assert!(result.is_err());
    }

    #[test]
    fn boundary() {
        let (env, _id, client) = setup();
        let real_admin = Address::generate(&env);
        client.initialize(&None);
        assert_ne!(client.get_admin(), real_admin);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.admin_action();
        }));
        assert!(result.is_err());
    }

    #[test]
    fn secure_path() {
        use crate::secure::SecureCurrentContractAdminClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureCurrentContractAdmin);
        let client = SecureCurrentContractAdminClient::new(&env, &id);

        let missing = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize_required(&None);
        }));
        assert!(missing.is_err());

        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        client.admin_action();
        assert_eq!(client.value(), 1);
    }
}
