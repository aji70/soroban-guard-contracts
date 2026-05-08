//! VULNERABLE: Unbounded Loop — Instruction Limit DoS
//!
//! An airdrop contract where `distribute_all()` iterates over every registered
//! user in a single transaction. Once the user list grows large enough the
//! transaction exceeds Soroban's per-transaction instruction limit and panics,
//! permanently bricking the distribution function.
//!
//! VULNERABILITY: Unbounded iteration over a growing `Vec<Address>` in one
//! call. There is no pagination, so the work per transaction is O(n) with no
//! upper bound enforced by the contract.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, vec, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Users,
    Balance(Address),
}

#[contract]
pub struct AirdropContract;

#[contractimpl]
impl AirdropContract {
    pub fn register(env: Env, user: Address) {
        let mut users: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Users)
            .unwrap_or(vec![&env]);
        users.push_back(user);
        env.storage().persistent().set(&DataKey::Users, &users);
    }

    /// VULNERABLE: iterates over ALL users in one transaction.
    /// With enough users this exceeds the instruction limit and panics.
    pub fn distribute_all(env: Env, amount_per_user: i128) {
        let users: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Users)
            .unwrap_or(vec![&env]);

        // ❌ Unbounded loop — O(n) with no cap
        for user in users.iter() {
            let key = DataKey::Balance(user.clone());
            let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            env.storage().persistent().set(&key, &(bal + amount_per_user));
        }
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn user_count(env: Env) -> u32 {
        let users: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Users)
            .unwrap_or(vec![&env]);
        users.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Small user set distributes correctly.
    #[test]
    fn test_distribute_small_set() {
        let env = Env::default();
        let id = env.register_contract(None, AirdropContract);
        let client = AirdropContractClient::new(&env, &id);

        let users: Vec<Address> = (0..5).map(|_| Address::generate(&env)).collect();
        for u in &users {
            client.register(u);
        }

        client.distribute_all(&100);

        for u in &users {
            assert_eq!(client.balance(u), 100);
        }
    }

    /// Large user set causes instruction limit panic — demonstrates DoS.
    /// Soroban's test environment enforces a budget; we set a tight budget to
    /// simulate the on-chain instruction limit being exceeded.
    #[test]
    #[should_panic]
    fn test_distribute_large_set_hits_limit() {
        let env = Env::default();
        // Enforce a tight CPU instruction budget to simulate on-chain limits
        env.budget().reset_limits(500_000, 100_000);

        let id = env.register_contract(None, AirdropContract);
        let client = AirdropContractClient::new(&env, &id);

        // Register enough users to blow the budget in a single distribute_all call
        for _ in 0..200 {
            client.register(&Address::generate(&env));
        }

        // ❌ VULNERABLE: exceeds instruction budget — panics
        client.distribute_all(&100);
    }
}
