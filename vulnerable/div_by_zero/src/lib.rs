//! VULNERABLE: Division by Zero
//!
//! A staking contract that distributes rewards by dividing `total_reward` by
//! `total_staked`. When the pool is empty (`total_staked == 0`) the division
//! panics, giving any caller a reliable denial-of-service vector.
//!
//! VULNERABILITY: No zero-check on `total_staked` before division.
//! SEVERITY: Medium
//!
//! SECURE MIRROR: check `total_staked == 0` and return 0 (or an error) before
//! performing the division.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    TotalStaked,
    Stake(Address),
}

#[contract]
pub struct StakingContract;

#[contractimpl]
impl StakingContract {
    /// Record a stake for `staker`. Requires auth. Updates both per-staker and total staked amounts.
    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        let prev: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(staker.clone()))
            .unwrap_or(0);
        let total: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalStaked)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker), &(prev + amount));
        env.storage()
            .persistent()
            .set(&DataKey::TotalStaked, &(total + amount));
    }

    /// VULNERABLE: panics when `total_staked == 0` — DoS vector.
    pub fn distribute_rewards(env: Env, total_reward: u64) -> u64 {
        let total_staked: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalStaked)
            .unwrap_or(0);
        // ❌ Panics if total_staked == 0 — DoS vector
        total_reward / total_staked
    }

    /// Returns the staked amount for `staker`, defaulting to 0.
    pub fn staked_amount(env: Env, staker: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }

    /// Returns the total amount staked across all stakers, defaulting to 0.
    pub fn total_staked(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalStaked)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, StakingContractClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &id);
        (env, client)
    }

    #[test]
    fn test_normal_distribution() {
        let (env, client) = setup();
        let staker = Address::generate(&env);
        env.mock_all_auths();

        client.stake(&staker, &500);
        // 1000 reward / 500 staked = 2 per token
        assert_eq!(client.distribute_rewards(&1000), 2);
    }

    /// Demonstrates the DoS vulnerability: calling distribute_rewards with an
    /// empty pool panics.
    #[test]
    #[should_panic]
    fn test_div_by_zero_panics_when_pool_empty() {
        let (_env, client) = setup();
        client.distribute_rewards(&1000);
    }

    #[test]
    fn test_single_staker_receives_full_reward_ratio() {
        let (env, client) = setup();
        let staker = Address::generate(&env);
        env.mock_all_auths();

        client.stake(&staker, &1);
        // 100 reward / 1 staked = 100
        assert_eq!(client.distribute_rewards(&100), 100);
    }
}
