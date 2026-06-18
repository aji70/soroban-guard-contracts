//! SECURE: Reward Checkpoint Fixed
//!
//! A corrected staking contract that properly snapshots the accumulator into
//! the user's reward checkpoint. When stake() is called, reward_debt is
//! immediately set to acc * new_stake, ensuring users only earn rewards from
//! the moment they deposit forward.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum SecureDataKey {
    /// Global accumulated reward per staked token (scaled ×1e7).
    AccRewardPerShare,
    /// Amount staked by each user.
    Stake(Address),
    /// Reward debt: acc_reward_per_share × stake at the time of last deposit/claim.
    RewardDebt(Address),
}

fn get_acc_secure(env: &Env) -> u64 {
    env.storage()
        .persistent()
        .get(&SecureDataKey::AccRewardPerShare)
        .unwrap_or(0)
}

fn get_stake_secure(env: &Env, user: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&SecureDataKey::Stake(user.clone()))
        .unwrap_or(0)
}

fn get_debt_secure(env: &Env, user: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&SecureDataKey::RewardDebt(user.clone()))
        .unwrap_or(0)
}

fn set_debt_secure(env: &Env, user: &Address, debt: u64) {
    env.storage()
        .persistent()
        .set(&SecureDataKey::RewardDebt(user.clone()), &debt);
}

#[contract]
pub struct SecureStaking;

#[contractimpl]
impl SecureStaking {
    pub fn initialize(env: Env, acc_reward_per_share: u64) {
        env.storage()
            .persistent()
            .set(&SecureDataKey::AccRewardPerShare, &acc_reward_per_share);
    }

    /// Advance the global accumulator (called by keeper / admin).
    pub fn add_rewards(env: Env, reward_per_share_delta: u64) {
        let acc = get_acc_secure(&env).saturating_add(reward_per_share_delta);
        env.storage()
            .persistent()
            .set(&SecureDataKey::AccRewardPerShare, &acc);
    }

    /// ✅ SECURE: Records the new stake balance AND immediately sets reward_debt
    /// to the current accumulator value. This ensures users only earn rewards
    /// from the moment they deposit, not from historical rewards.
    pub fn stake(env: Env, user: Address, amount: u64) {
        user.require_auth();
        let new_total_stake = get_stake_secure(&env, &user).saturating_add(amount);
        let acc = get_acc_secure(&env);

        // Write the new balance
        env.storage()
            .persistent()
            .set(&SecureDataKey::Stake(user.clone()), &new_total_stake);

        // ✅ FIX: Set reward_debt to the current accumulator × new stake.
        // This captures the checkpoint, so pending = 0 at deposit time.
        let new_debt = acc.saturating_mul(new_total_stake) / 1_000_0000;
        set_debt_secure(&env, &user, new_debt);
    }

    /// Pays out pending rewards. Now only covers the window after stake() was called.
    pub fn claim_rewards(env: Env, user: Address) -> u64 {
        user.require_auth();
        let stake = get_stake_secure(&env, &user);
        let acc = get_acc_secure(&env);
        let entitled = acc.saturating_mul(stake) / 1_000_0000;
        let debt = get_debt_secure(&env, &user);
        let pending = entitled.saturating_sub(debt);
        // Update debt so repeated claims don't double-pay.
        set_debt_secure(&env, &user, entitled);
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_with_existing_rewards() -> (Env, SecureStakingClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureStaking);
        let client = SecureStakingClient::new(&env, &id);
        // Rewards already accrued before the late depositor arrives.
        client.initialize(&5_000_000_000);
        let late_user = Address::generate(&env);
        (env, client, late_user)
    }

    /// ✅ Test: Late staker cannot claim pre-deposit rewards.
    /// After staking with the checkpoint fix, immediate claim_rewards returns 0.
    #[test]
    fn test_secure_late_staker_cannot_claim_past_rewards() {
        let (_env, client, user) = setup_with_existing_rewards();
        client.stake(&user, &1_000);
        // With the fix: debt = 5_000_000_000 * 1_000 / 10_000_000 = 500_000
        // pending = entitled - debt = (5_000_000_000 * 1_000 / 10_000_000) - 500_000 = 0
        let reward = client.claim_rewards(&user);
        assert_eq!(
            reward, 0,
            "secure: late staker cannot claim pre-deposit rewards"
        );
    }

    /// ✅ Test: Early staker (before any rewards) earns correctly.
    /// Stake initially, distribute rewards, claim; verify reward = elapsed_acc × stake.
    #[test]
    fn test_secure_early_staker_earns_correctly() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureStaking);
        let client = SecureStakingClient::new(&env, &id);
        client.initialize(&0); // Start with no accumulated rewards
        let user = Address::generate(&env);

        // User stakes before any rewards accrue
        client.stake(&user, &1_000);
        // debt = 0 * 1_000 / 10_000_000 = 0

        // Now add rewards
        client.add_rewards(&5_000_000_000);
        // acc is now 5_000_000_000

        // Claim: pending = (5_000_000_000 * 1_000 / 10_000_000) - 0 = 500_000
        let reward = client.claim_rewards(&user);
        assert_eq!(reward, 500_000, "early staker earns correctly");
    }

    /// ✅ Test: Increasing stake resets debt correctly.
    /// Initial stake + rewards, then increase stake; verify only the new window
    /// generates rewards, not a windfall from missed debt update.
    #[test]
    fn test_secure_stake_increase_resets_debt() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureStaking);
        let client = SecureStakingClient::new(&env, &id);
        client.initialize(&0);
        let user = Address::generate(&env);

        // Initial stake
        client.stake(&user, &1_000);
        // debt = 0 * 1_000 / 10_000_000 = 0

        // Add rewards
        client.add_rewards(&2_000_000_000);
        // acc = 2_000_000_000

        // Claim to consume the first window
        let first_reward = client.claim_rewards(&user);
        // pending = (2_000_000_000 * 1_000 / 10_000_000) - 0 = 200_000
        assert_eq!(first_reward, 200_000);
        // After claim, debt = 200_000

        // Add more rewards
        client.add_rewards(&3_000_000_000);
        // acc = 5_000_000_000

        // Increase stake by 500
        client.stake(&user, &500);
        // new_total = 1_500, new_debt = 5_000_000_000 * 1_500 / 10_000_000 = 750_000

        // Claim again: should only include rewards earned since the stake increase
        let second_reward = client.claim_rewards(&user);
        // entitled = 5_000_000_000 * 1_500 / 10_000_000 = 750_000
        // debt before claim = 750_000 (set at stake increase time)
        // pending = 750_000 - 750_000 = 0
        assert_eq!(
            second_reward, 0,
            "stake increase resets debt; no windfall on claim"
        );
    }
}
