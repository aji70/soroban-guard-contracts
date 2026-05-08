//! VULNERABLE: Double Claim / Stale Timestamp
//!
//! A staking contract where `claim_rewards` computes the reward based on
//! elapsed ledgers since `staked_at`, but **never resets `staked_at`**.
//! This means the same elapsed time can be claimed over and over, draining
//! the reward pool.
//!
//! VULNERABILITY: Missing `set_staked_at` after reward calculation — the
//! timestamp is never advanced, so every subsequent call re-uses the same
//! elapsed window.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Stake(Address),
    StakedAt(Address),
    RewardRate,
}

fn get_stake(env: &Env, staker: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(staker.clone()))
        .unwrap_or(0)
}

fn get_staked_at(env: &Env, staker: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::StakedAt(staker.clone()))
        .unwrap_or(0)
}

fn set_staked_at(env: &Env, staker: &Address, seq: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::StakedAt(staker.clone()), &seq);
}

fn get_rate(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::RewardRate)
        .unwrap_or(0)
}

#[contract]
pub struct DoubleClaim;

#[contractimpl]
impl DoubleClaim {
    /// Initialise the contract with a reward rate (tokens per ledger per staked token).
    pub fn initialize(env: Env, reward_rate: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    /// Record a stake for `staker` and snapshot the current ledger sequence as `staked_at`.
    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        set_staked_at(&env, &staker, env.ledger().sequence());
    }

    /// VULNERABLE: reward is computed from elapsed ledgers since `staked_at`,
    /// but `staked_at` is never updated. Calling this twice with the same
    /// ledger gap yields the same reward both times.
    ///
    /// # Vulnerability
    /// Missing `set_staked_at` reset after payout. Impact: unlimited reward drain via repeated calls.
    pub fn claim_rewards(env: Env, staker: Address) -> u64 {
        staker.require_auth();
        let elapsed = env.ledger().sequence() - get_staked_at(&env, &staker);
        let reward = get_stake(&env, &staker)
            .checked_mul(get_rate(&env))
            .and_then(|v| v.checked_mul(elapsed as u64))
            .unwrap_or(0);
        // ❌ Missing: set_staked_at(&env, &staker, env.ledger().sequence());
        reward
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env,
    };

    fn setup() -> (Env, DoubleClaimClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, DoubleClaim);
        let client = DoubleClaimClient::new(&env, &id);
        client.initialize(&10);
        let staker = Address::generate(&env);
        client.stake(&staker, &100);
        (env, client, staker)
    }

    #[test]
    fn test_first_claim_correct() {
        let (env, client, staker) = setup();
        env.ledger().with_mut(|l| l.sequence_number += 5);
        // reward = 100 * 10 * 5 = 5000
        assert_eq!(client.claim_rewards(&staker), 5000);
    }

    /// Demonstrates the double-spend: a second immediate claim returns the
    /// same reward because `staked_at` was never reset.
    #[test]
    fn test_second_claim_same_reward_double_spend() {
        let (env, client, staker) = setup();
        env.ledger().with_mut(|l| l.sequence_number += 5);
        let first = client.claim_rewards(&staker);
        let second = client.claim_rewards(&staker);
        assert_eq!(first, second, "double-spend: same reward claimed twice");
    }

    /// Secure version: reset staked_at after each claim so elapsed resets to 0.
    #[test]
    fn test_secure_version_resets_timestamp() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, DoubleClaim);
        let client = DoubleClaimClient::new(&env, &id);
        client.initialize(&10);
        let staker = Address::generate(&env);
        client.stake(&staker, &100);

        env.ledger().with_mut(|l| l.sequence_number += 5);
        let first = client.claim_rewards(&staker);
        assert_eq!(first, 5000);

        // Simulate what a secure contract would do: manually advance staked_at
        // so the second claim on the same ledger yields 0.
        // (In the fixed contract, claim_rewards itself would call set_staked_at.)
        env.as_contract(&id, || {
            set_staked_at(&env, &staker, env.ledger().sequence());
        });

        let second = client.claim_rewards(&staker);
        assert_eq!(second, 0, "after reset, no new elapsed time → reward = 0");
    }
}
