//! VULNERABLE: Reward Checkpoint Missing
//!
//! A staking contract that uses a global accumulator pattern but does NOT
//! snapshot the accumulator into the user's reward checkpoint before
//! crediting new stake. A user who deposits after rewards have already
//! accrued can immediately claim those pre-deposit rewards as if they had
//! been staking all along.
//!
//! VULNERABILITY: `stake` writes the new balance before (or without)
//! setting `reward_debt` to the current accumulator value. The user's
//! debt starts at 0, so `pending = acc * new_stake - 0` includes all
//! historical rewards.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    /// Global accumulated reward per staked token (scaled ×1e7).
    AccRewardPerShare,
    /// Amount staked by each user.
    Stake(Address),
    /// Reward debt: acc_reward_per_share × stake at the time of last deposit/claim.
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
pub struct RewardCheckpointMissing;

#[contractimpl]
impl RewardCheckpointMissing {
    pub fn initialize(env: Env, acc_reward_per_share: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::AccRewardPerShare, &acc_reward_per_share);
    }

    /// Advance the global accumulator (called by keeper / admin).
    pub fn add_rewards(env: Env, reward_per_share_delta: u64) {
        let acc = get_acc(&env).saturating_add(reward_per_share_delta);
        env.storage()
            .persistent()
            .set(&DataKey::AccRewardPerShare, &acc);
    }

    /// VULNERABLE: records the new stake balance but does NOT set reward_debt
    /// to `acc * new_stake`. The debt defaults to 0, so the user appears
    /// entitled to all rewards since the contract was deployed.
    ///
    /// # Vulnerability
    /// Missing `set_debt(&env, &user, get_acc(&env) * amount / SCALE)` before
    /// or after writing the stake. Impact: late depositors steal historical rewards.
    pub fn stake(env: Env, user: Address, amount: u64) {
        user.require_auth();
        // ❌ Missing: set_debt(&env, &user, get_acc(&env).saturating_mul(amount) / 1_000_0000);
        env.storage()
            .persistent()
            .set(&DataKey::Stake(user.clone()), &amount);
    }

    /// Pays out pending rewards correctly (the bug is in stake, not here).
    pub fn claim_rewards(env: Env, user: Address) -> u64 {
        user.require_auth();
        let stake = get_stake(&env, &user);
        let acc = get_acc(&env);
        let entitled = acc.saturating_mul(stake) / 1_000_0000;
        let debt = get_debt(&env, &user);
        let pending = entitled.saturating_sub(debt);
        // Update debt so repeated claims don't double-pay.
        set_debt(&env, &user, entitled);
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_with_existing_rewards() -> (Env, RewardCheckpointMissingClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, RewardCheckpointMissing);
        let client = RewardCheckpointMissingClient::new(&env, &id);
        // Rewards already accrued before the late depositor arrives.
        client.initialize(&5_000_000_000);
        let late_user = Address::generate(&env);
        (env, client, late_user)
    }

    /// Demonstrates the vulnerability: a user who stakes AFTER rewards have
    /// already accrued can immediately claim those historical rewards.
    #[test]
    fn test_late_depositor_claims_historical_rewards() {
        let (_env, client, user) = setup_with_existing_rewards();
        client.stake(&user, &1_000);
        // pending = (5_000_000_000 * 1_000) / 10_000_000 - 0 = 500_000
        let reward = client.claim_rewards(&user);
        assert!(
            reward > 0,
            "vulnerability: late depositor claims pre-deposit rewards"
        );
    }

    /// Secure version: stake sets the checkpoint so pending starts at 0.
    #[test]
    fn test_secure_checkpoint_on_stake_yields_zero_pending() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, RewardCheckpointMissing);
        let client = RewardCheckpointMissingClient::new(&env, &id);
        client.initialize(&5_000_000_000);
        let user = Address::generate(&env);
        client.stake(&user, &1_000);

        // Simulate what a secure contract would do: set debt at deposit time.
        env.as_contract(&id, || {
            let acc = get_acc(&env);
            let amount = get_stake(&env, &user);
            let debt = acc.saturating_mul(amount) / 1_000_0000;
            set_debt(&env, &user, debt);
        });

        let reward = client.claim_rewards(&user);
        assert_eq!(
            reward, 0,
            "with checkpoint set, no pre-deposit rewards claimable"
        );
    }

    /// After staking with the bug, new rewards added post-deposit are still
    /// correctly attributed (the bug only affects pre-deposit history).
    #[test]
    fn test_post_deposit_rewards_still_accrue() {
        let (_env, client, user) = setup_with_existing_rewards();
        client.stake(&user, &1_000);
        // Drain the incorrectly claimable amount first.
        client.claim_rewards(&user);
        // Now add fresh rewards.
        client.add_rewards(&1_000_000_000);
        let reward = client.claim_rewards(&user);
        // pending = (1_000_000_000 * 1_000) / 10_000_000 = 100_000
        assert!(reward > 0, "post-deposit rewards accrue correctly");
    }
}
