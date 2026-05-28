//! SECURE mirror: require admin auth and allowlist validation before storing a fee collector.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

#[contract]
pub struct SecureFeeCollector;

#[contractimpl]
impl SecureFeeCollector {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
    }

    /// ✅ Only admin can change the collector, and only to an approved address.
    pub fn set_collector(env: Env, collector: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Approved)
            .unwrap_or(Vec::new(&env));
        assert!(list.contains(&collector), "collector not approved");

        env.storage().persistent().set(&DataKey::Collector, &collector);
    }

    pub fn add_approved(env: Env, collector: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        let mut list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Approved)
            .unwrap_or(Vec::new(&env));
        list.push_back(collector);
        env.storage().persistent().set(&DataKey::Approved, &list);
    }

    pub fn collect_fee(env: Env, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let fee = amount / 100;
        let current: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &(current + fee));
    }

    pub fn get_fees(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Fees).unwrap_or(0)
    }

    pub fn get_collector(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Collector)
            .expect("collector not set")
    }
}
