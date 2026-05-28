//! SECURE mirror: require admin auth and allowlist validation before storing an oracle.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

#[contract]
pub struct SecureOracleSetter;

#[contractimpl]
impl SecureOracleSetter {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// ✅ Admin auth required; oracle must be on the allowlist.
    pub fn set_oracle(env: Env, oracle: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Allowlist)
            .unwrap_or(Vec::new(&env));
        assert!(list.contains(&oracle), "oracle not on allowlist");

        env.storage().persistent().set(&DataKey::Oracle, &oracle);
    }

    pub fn add_to_allowlist(env: Env, oracle: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        let mut list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Allowlist)
            .unwrap_or(Vec::new(&env));
        list.push_back(oracle);
        env.storage().persistent().set(&DataKey::Allowlist, &list);
    }

    pub fn get_oracle(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Oracle)
            .expect("oracle not set")
    }
}
