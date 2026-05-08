//! VULNERABLE: Unchecked Arithmetic
//!
//! A staking contract that calculates rewards using raw `+` and `*` on u64
//! values. With `overflow-checks = true` in release profile this panics, but
//! in debug builds (or if the profile flag is removed) it silently wraps,
//! producing wildly incorrect reward amounts.
//!
//! VULNERABILITY: Raw arithmetic operators instead of `checked_add` /
//! `checked_mul` — overflow is not explicitly handled.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Stake(Address),
    StakedAt(Address),
    RewardRate, // tokens per ledger per staked token (scaled by 1_000_000)
}

#[contract]
pub struct StakingContract;

#[contractimpl]
impl StakingContract {
    /// Initialise the contract with a reward rate (tokens per ledger per staked token).
    pub fn initialize(env: Env, reward_rate: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    /// Record a stake for `staker` and snapshot the current ledger sequence.
    /// Requires `staker` auth. Amount is stored as-is with no overflow guard.
    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker), &env.ledger().sequence());
    }

    /// VULNERABLE: reward = staked_amount * rate * elapsed_ledgers
    /// All three values are u64 — multiplying large staked amounts by many
    /// elapsed ledgers overflows without any checked arithmetic.
    pub fn claim_rewards(env: Env, staker: Address) -> u64 {
        staker.require_auth();

        let staked: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(staker.clone()))
            .unwrap_or(0);

        let staked_at: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::StakedAt(staker.clone()))
            .unwrap_or(0);

        let rate: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0);

        let current_ledger = env.ledger().sequence();
        let elapsed = (current_ledger - staked_at) as u64;

        // ❌ Raw * can overflow for large staked amounts or long durations
        let reward = staked * rate * elapsed;

        // Reset stake timestamp after claim
        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker), &current_ledger);

        reward
    }

    /// Returns the staked amount for `staker`, or 0 if not staked.
    pub fn staked_amount(env: Env, staker: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_stake_and_claim_basic() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &contract_id);

        let staker = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&10);
        client.stake(&staker, &100);
        assert_eq!(client.staked_amount(&staker), 100);
    }

    #[test]
    fn test_claim_rewards_zero_elapsed() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &contract_id);

        let staker = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&100);
        client.stake(&staker, &1000);

        // Same ledger — elapsed = 0, reward = 0
        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 0);
    }

    /// Demonstrates the vulnerability: large values overflow without checked math.
    #[test]
    #[should_panic]
    fn test_overflow_with_large_values() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &contract_id);

        let staker = Address::generate(&env);
        env.mock_all_auths();

        // rate=u64::MAX, staked=2 — first multiplication already overflows
        client.initialize(&u64::MAX);
        client.stake(&staker, &2);
        client.claim_rewards(&staker);
    }
}
