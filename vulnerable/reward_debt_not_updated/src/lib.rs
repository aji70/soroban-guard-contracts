//! VULNERABLE: Reward Debt Not Updated
//!
//! A staking contract that tracks per-user reward debt to implement a
//! global accumulator pattern. `claim_rewards` pays out pending rewards
//! but **never updates `reward_debt`**, so the same accrued amount can be
//! claimed repeatedly until the pool is drained.
//!
//! VULNERABILITY: `claim_rewards` omits `set_reward_debt` after payout.
//! Impact: unlimited reward drain via repeated calls.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    /// Total accumulated reward per staked token (scaled ×1e7).
    AccRewardPerShare,
    /// Amount staked by each user.
    Stake(Address),
    /// Reward debt snapshot for each user (acc_reward_per_share at last claim × stake).
    RewardDebt(Address),
}

fn get_acc(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::AccRewardPerShare)
        .unwrap_or(0)
}

fn get_stake(env: &Env, user: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(user.clone()))
        .unwrap_or(0)
}

fn get_debt(env: &Env, user: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::RewardDebt(user.clone()))
        .unwrap_or(0)
}

fn set_debt(env: &Env, user: &Address, debt: u64) {
    env.storage()
        .persistent()
        .set(&DataKey::RewardDebt(user.clone()), &debt);
}

#[contract]
pub struct RewardDebtNotUpdated;

#[contractimpl]
impl RewardDebtNotUpdated {
    /// Seed the global accumulator (simulates rewards already accrued).
    pub fn initialize(env: Env, acc_reward_per_share: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::AccRewardPerShare, &acc_reward_per_share);
    }

    /// Deposit stake and snapshot current debt correctly.
    pub fn stake(env: Env, user: Address, amount: u64) {
        user.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(user.clone()), &amount);
        // Correct: snapshot debt at deposit time so pre-deposit rewards are excluded.
        let debt = get_acc(&env).saturating_mul(amount) / 1_000_0000;
        set_debt(&env, &user, debt);
    }

    /// Advance the global accumulator (called by keeper / admin).
    pub fn add_rewards(env: Env, reward_per_share_delta: u64) {
        let acc = get_acc(&env).saturating_add(reward_per_share_delta);
        env.storage()
            .persistent()
            .set(&DataKey::AccRewardPerShare, &acc);
    }

    /// VULNERABLE: pays pending rewards but does NOT update reward_debt.
    /// Calling this twice returns the same pending amount both times.
    ///
    /// # Vulnerability
    /// Missing `set_debt` after payout. Every call re-computes the same
    /// `pending` value because the debt snapshot is never advanced.
    pub fn claim_rewards(env: Env, user: Address) -> u64 {
        user.require_auth();
        let stake = get_stake(&env, &user);
        let acc = get_acc(&env);
        let entitled = acc.saturating_mul(stake) / 1_000_0000;
        let debt = get_debt(&env, &user);
        let pending = entitled.saturating_sub(debt);
        // ❌ Missing: set_debt(&env, &user, entitled);
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, RewardDebtNotUpdatedClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, RewardDebtNotUpdated);
        let client = RewardDebtNotUpdatedClient::new(&env, &id);
        // acc_reward_per_share = 0 initially; user stakes, then rewards accrue.
        client.initialize(&0);
        let user = Address::generate(&env);
        client.stake(&user, &1_000);
        // Simulate keeper adding rewards: 500 per share (×1e7 scaled → 5_000_000_000).
        client.add_rewards(&5_000_000_000);
        (env, client, user)
    }

    #[test]
    fn test_first_claim_correct() {
        let (_env, client, user) = setup();
        // pending = (5_000_000_000 * 1_000) / 10_000_000 - 0 = 500_000
        let reward = client.claim_rewards(&user);
        assert!(reward > 0, "first claim should yield rewards");
    }

    /// Demonstrates the vulnerability: a second immediate claim returns the
    /// same amount because reward_debt was never updated.
    #[test]
    fn test_repeated_claim_drains_pool() {
        let (_env, client, user) = setup();
        let first = client.claim_rewards(&user);
        let second = client.claim_rewards(&user);
        assert_eq!(
            first, second,
            "vulnerability: same reward claimable repeatedly"
        );
        assert!(first > 0);
    }

    /// Secure version: after updating debt, a second claim yields 0.
    #[test]
    fn test_secure_debt_update_prevents_double_claim() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, RewardDebtNotUpdated);
        let client = RewardDebtNotUpdatedClient::new(&env, &id);
        client.initialize(&0);
        let user = Address::generate(&env);
        client.stake(&user, &1_000);
        client.add_rewards(&5_000_000_000);

        let first = client.claim_rewards(&user);
        assert!(first > 0);

        // Simulate what a secure contract would do: update debt after payout.
        env.as_contract(&id, || {
            let acc = get_acc(&env);
            let stake = get_stake(&env, &user);
            let entitled = acc.saturating_mul(stake) / 1_000_0000;
            set_debt(&env, &user, entitled);
        });

        let second = client.claim_rewards(&user);
        assert_eq!(second, 0, "after debt update, no pending rewards remain");
    }
}
