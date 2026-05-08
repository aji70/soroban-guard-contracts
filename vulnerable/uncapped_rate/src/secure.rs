use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{DataKey, MAX_RATE};

#[contract]
pub struct SecureStakingContract;

#[contractimpl]
impl SecureStakingContract {
    pub fn initialize(env: Env, admin: Address, reward_rate: u64) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    /// SECURE: enforces an upper bound on the reward rate to prevent
    /// a malicious admin from draining the reward pool.
    pub fn update_rate(env: Env, new_rate: u64) {
        Self::require_admin(&env);
        // ✅ Enforce maximum rate to prevent pool drain.
        assert!(new_rate <= MAX_RATE, "rate exceeds maximum");
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &new_rate);
    }

    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker), &env.ledger().sequence());
    }

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

        let reward = staked * rate * elapsed;

        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker), &current_ledger);

        reward
    }

    pub fn staked_amount(env: Env, staker: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }

    pub fn current_rate(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("admin not initialized");
        admin.require_auth();
    }
}

