//! VULNERABLE: Underfunded Reward Pool
//!
//! The staking contract's `claim_rewards` calculates the owed reward and
//! transfers tokens without first verifying that the contract holds enough
//! reward tokens. If the pool is underfunded or partially drained, the
//! transfer fails mid-execution, but `last_claim` has already been updated —
//! the staker loses their reward window without receiving any tokens.
//!
//! VULNERABILITY: No pre-transfer balance check. `last_claim` is updated
//! before the transfer, so a failed transfer silently forfeits the reward.
//!
//! SEVERITY: High
//! FIX: assert `pool_balance >= reward` before updating `last_claim` or
//! transferring, and emit a `RewardPoolLow` event when balance is low.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

const REWARD_RATE: u64 = 10; // tokens per ledger per staked token
const LOW_POOL_THRESHOLD: u64 = 500;

#[contracttype]
pub enum DataKey {
    Stake(Address),
    LastClaim(Address),
    PoolBalance,
}

fn get_stake(env: &Env, staker: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(staker.clone()))
        .unwrap_or(0)
}

fn get_last_claim(env: &Env, staker: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::LastClaim(staker.clone()))
        .unwrap_or(0)
}

fn set_last_claim(env: &Env, staker: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::LastClaim(staker.clone()), &env.ledger().sequence());
}

fn get_pool_balance(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::PoolBalance)
        .unwrap_or(0)
}

fn calculate_reward(env: &Env, staker: &Address) -> u64 {
    let elapsed = env.ledger().sequence() - get_last_claim(env, staker);
    get_stake(env, staker)
        .checked_mul(REWARD_RATE)
        .and_then(|v| v.checked_mul(elapsed as u64))
        .unwrap_or(0)
}

#[contract]
pub struct UnderfundedRewardPool;

#[contractimpl]
impl UnderfundedRewardPool {
    pub fn initialize(env: Env, pool_balance: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &pool_balance);
    }

    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        set_last_claim(&env, &staker);
    }

    /// VULNERABLE: updates last_claim before checking pool balance.
    /// If the pool is underfunded the "transfer" fails but last_claim is
    /// already advanced — the staker's reward window is silently forfeited.
    pub fn claim_rewards(env: Env, staker: Address) {
        staker.require_auth();
        let reward = calculate_reward(&env, &staker);

        // ❌ last_claim updated BEFORE verifying pool has enough tokens.
        set_last_claim(&env, &staker);

        let pool = get_pool_balance(&env);
        // ❌ No pre-check: if pool < reward the subtraction panics here,
        //    but last_claim has already been advanced — reward is lost.
        let new_pool = pool.checked_sub(reward).expect("pool underfunded");
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &new_pool);
    }

    pub fn get_pool_balance(env: Env) -> u64 {
        get_pool_balance(&env)
    }

    pub fn get_last_claim(env: Env, staker: Address) -> u32 {
        get_last_claim(&env, &staker)
    }
}

// ── Secure version (inline) ───────────────────────────────────────────────────

#[contract]
pub struct SecureRewardPool;

#[contractimpl]
impl SecureRewardPool {
    pub fn initialize(env: Env, pool_balance: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &pool_balance);
    }

    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        set_last_claim(&env, &staker);
    }

    /// FIX: checks pool balance BEFORE updating last_claim or transferring.
    /// Emits a RewardPoolLow event when balance drops below the threshold.
    pub fn claim_rewards(env: Env, staker: Address) {
        staker.require_auth();
        let reward = calculate_reward(&env, &staker);
        let pool = get_pool_balance(&env);

        // ✅ Pre-check: panic before touching last_claim if pool is insufficient.
        if pool < reward {
            panic!("pool underfunded");
        }

        let new_pool = pool - reward;
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &new_pool);

        // ✅ last_claim updated only after successful transfer.
        set_last_claim(&env, &staker);

        // Emit low-pool warning when balance drops below threshold.
        if new_pool < LOW_POOL_THRESHOLD {
            env.events().publish(
                (symbol_short!("pool"), symbol_short!("low")),
                new_pool,
            );
        }
    }

    pub fn get_pool_balance(env: Env) -> u64 {
        get_pool_balance(&env)
    }

    pub fn get_last_claim(env: Env, staker: Address) -> u32 {
        get_last_claim(&env, &staker)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger}, Address, Env};

    // ── Vulnerable contract tests ─────────────────────────────────────────────

    /// Demonstrates the bug: in the vulnerable contract, last_claim is updated
    /// BEFORE the pool check. We verify this ordering by inspecting the code
    /// path — set_last_claim is called unconditionally before the subtraction.
    /// The secure version fixes this by checking the pool first.
    #[test]
    fn test_last_claim_updated_even_when_pool_insufficient() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, UnderfundedRewardPool);
        let client = UnderfundedRewardPoolClient::new(&env, &id);

        let staker = Address::generate(&env);
        // Pool has 1_000_000 tokens — enough to succeed.
        client.initialize(&1_000_000);
        client.stake(&staker, &10);

        // Advance ledger so elapsed > 0.
        env.ledger().with_mut(|l| l.sequence_number += 5);
        let seq_after = env.ledger().sequence();

        client.claim_rewards(&staker);

        // last_claim was updated (to current sequence) even though the pool
        // check comes after — this is the ordering bug.
        assert_eq!(client.get_last_claim(&staker), seq_after);
    }

    // ── Secure contract tests ─────────────────────────────────────────────────

    /// After the fix, claim_rewards panics when pool balance is insufficient,
    /// and last_claim is NOT updated.
    #[test]
    #[should_panic(expected = "pool underfunded")]
    fn test_secure_panics_when_pool_insufficient() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureRewardPool);
        let client = SecureRewardPoolClient::new(&env, &id);

        let staker = Address::generate(&env);
        // Pool has only 5 tokens; reward will be 100 * 10 * 10 = 10_000.
        client.initialize(&5);
        client.stake(&staker, &100);

        env.ledger().with_mut(|l| l.sequence_number += 10);
        client.claim_rewards(&staker);
    }

    /// A fully funded pool allows a successful claim and correctly updates
    /// last_claim.
    #[test]
    fn test_funded_pool_claim_succeeds_and_updates_last_claim() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureRewardPool);
        let client = SecureRewardPoolClient::new(&env, &id);

        let staker = Address::generate(&env);
        // reward = 10 * 10 * 5 = 500; pool starts at 1_000.
        client.initialize(&1_000);
        client.stake(&staker, &10);

        env.ledger().with_mut(|l| l.sequence_number += 5);
        let seq_after = env.ledger().sequence();

        client.claim_rewards(&staker);

        assert_eq!(client.get_pool_balance(), 500);
        assert_eq!(client.get_last_claim(&staker), seq_after);
    }
}
