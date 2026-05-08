//! VULNERABLE: Missing Zero-Address Check on Initialize
//!
//! A contract where `initialize(admin)` stores the admin without validating
//! that it is a real, non-default address. Passing the zero/default address
//! permanently bricks all admin-gated functions.
//!
//! VULNERABILITY: `initialize` never asserts that `admin` is a valid non-zero
//! address, so a caller can pass the Stellar zero address and lock the contract
//! forever — no one can ever satisfy `require_auth` for that address.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

const ZERO_ADDR: &str = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

#[contracttype]
pub enum DataKey {
    Admin,
    Value,
}

#[contract]
pub struct ZeroAdminContract;

#[contractimpl]
impl ZeroAdminContract {
    /// Fix: reject the zero address when setting the admin.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        let zero_admin = Address::from_string(&String::from_str(&env, ZERO_ADDR));
        if admin == zero_admin {
            panic!("admin must not be zero address");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Admin-gated function — valid non-zero admin can still use this.
    pub fn set_value(env: Env, value: i128) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Value, &value);
    }

    /// Returns the stored config value, defaulting to 0.
    pub fn get_value(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Value).unwrap_or(0)
    }

    /// Returns the stored admin address. Panics if not yet initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, ZeroAdminContractClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, ZeroAdminContract);
        let client = ZeroAdminContractClient::new(&env, &id);
        (env, client)
    }

    /// A valid admin address initializes correctly.
    #[test]
    fn test_valid_admin_initializes() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
    }

    /// Reject the zero address as admin during initialization.
    #[test]
    #[should_panic(expected = "admin must not be zero address")]
    fn test_zero_address_admin_panics() {
        let (env, client) = setup();
        let zero = Address::from_string(&String::from_str(&env, ZERO_ADDR));
        client.initialize(&zero);
    }

    /// A valid non-zero admin can still authenticate and use admin functions.
    #[test]
    fn test_valid_admin_can_set_value() {
        let (env, client) = setup();
        let admin = Address::generate(&env);

        client.initialize(&admin);
        env.mock_all_auths();
        client.set_value(&42);

        assert_eq!(client.get_value(), 42);
    }
}
