use super::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

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

    /// SECURE: rejects the current contract address as collector.
    pub fn set_collector(env: Env, collector: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        // ✅ Prevent self-referential fee routing.
        assert!(
            collector != env.current_contract_address(),
            "collector cannot be the contract itself"
        );
        env.storage()
            .persistent()
            .set(&DataKey::Collector, &collector);
    }

    pub fn collect_fee(env: Env, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let collector: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Collector)
            .expect("collector not set");
        let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Fees, &(fees + amount));
        env.events()
            .publish((symbol_short!("fee"),), (collector, amount));
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
