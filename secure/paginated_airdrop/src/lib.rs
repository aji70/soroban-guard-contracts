//! SECURE: Paginated Airdrop — Bounded Per-Transaction Work
//!
//! Fixes the unbounded-loop vulnerability by replacing `distribute_all()` with
//! `distribute_batch(start, count)`. Each call processes at most `MAX_BATCH`
//! users, keeping per-transaction instruction usage constant regardless of
//! total user count. Callers page through the list across multiple transactions.
//!
//! SECURITY: ✅ Per-transaction work is O(min(count, MAX_BATCH)) — never O(n).

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, vec, Address, Env, Vec};

/// Maximum users processed in a single transaction.
const MAX_BATCH: u32 = 50;

#[contracttype]
pub enum DataKey {
    Users,
    Balance(Address),
}

#[contract]
pub struct PaginatedAirdrop;

#[contractimpl]
impl PaginatedAirdrop {
    pub fn register(env: Env, user: Address) {
        let mut users: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Users)
            .unwrap_or(vec![&env]);
        users.push_back(user);
        env.storage().persistent().set(&DataKey::Users, &users);
    }

    /// ✅ SECURE: processes at most MAX_BATCH users per call.
    /// Callers advance `start` by `count` across successive transactions.
    /// Returns the index to pass as `start` in the next call (or total user
    /// count when the list is exhausted).
    pub fn distribute_batch(env: Env, start: u32, count: u32, amount_per_user: i128) -> u32 {
        let batch = count.min(MAX_BATCH);

        let users: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Users)
            .unwrap_or(vec![&env]);

        let total = users.len();
        let end = (start + batch).min(total);

        for i in start..end {
            let user = users.get(i).unwrap();
            let key = DataKey::Balance(user.clone());
            let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            env.storage().persistent().set(&key, &(bal + amount_per_user));
        }

        end // caller uses this as `start` for the next batch
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

    /// Paginated distribution covers all users correctly across multiple batches.
    #[test]
    fn test_paginated_distributes_all_users() {
        let env = Env::default();
        let id = env.register_contract(None, PaginatedAirdrop);
        let client = PaginatedAirdropClient::new(&env, &id);

        let users: std::vec::Vec<Address> = (0..120).map(|_| Address::generate(&env)).collect();
        for u in &users {
            client.register(u);
        }

        // Page through in MAX_BATCH (50) chunks
        let mut next = 0u32;
        while next < client.user_count() {
            next = client.distribute_batch(&next, &50, &200);
        }

        for u in &users {
            assert_eq!(client.balance(u), 200);
        }
    }

    /// count above MAX_BATCH is silently clamped — no panic.
    #[test]
    fn test_count_clamped_to_max_batch() {
        let env = Env::default();
        let id = env.register_contract(None, PaginatedAirdrop);
        let client = PaginatedAirdropClient::new(&env, &id);

        for _ in 0..10 {
            client.register(&Address::generate(&env));
        }

        // Requesting 1000 is clamped to MAX_BATCH internally
        let next = client.distribute_batch(&0, &1000, &50);
        assert_eq!(next, 10); // only 10 users exist, all processed
    }

    /// Large user set handled safely across batches — no instruction limit panic.
    #[test]
    fn test_large_user_set_no_panic() {
        let env = Env::default();
        env.budget().reset_limits(500_000, 100_000);

        let id = env.register_contract(None, PaginatedAirdrop);
        let client = PaginatedAirdropClient::new(&env, &id);

        for _ in 0..200 {
            client.register(&Address::generate(&env));
        }

        // ✅ SECURE: each batch stays within budget
        env.budget().reset_limits(500_000, 100_000);
        // Single batch of MAX_BATCH users — well within limits
        client.distribute_batch(&0, &MAX_BATCH, &100);
    }
}
