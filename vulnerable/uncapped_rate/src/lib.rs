//! VULNERABLE: Uncapped Reward Rate
//!
//! A staking contract that allows the admin to update the reward rate
//! without an upper bound cap. A compromised or malicious admin can set
//! rate = u64::MAX, causing claim_rewards to drain the reward pool in a
//! single claim (or panic due to overflow).
//!
//! VULNERABILITY: No `assert!(new_rate <= MAX_RATE)` in `update_rate`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const MAX_RATE: u64 = 1_000_000;

#[contracttype]
pub enum DataKey {
    Stake(Address),
    StakedAt(Address),
    RewardRate,
    Admin,
}

#[contract]
pub struct StakingContract;

#[contractimpl]
impl StakingContract {
    /// Initialise the contract with an admin and initial reward rate.
    pub fn initialize(env: Env, admin: Address, reward_rate: u64) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    /// VULNERABLE: no upper bound check on new_rate.
    /// A malicious admin can set rate = u64::MAX and drain the pool.
    pub fn update_rate(env: Env, new_rate: u64) {
        Self::require_admin(&env);
        // ❌ No upper bound — admin can set rate to u64::MAX
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &new_rate);
    }

    /// Record a stake for `staker`. Requires staker auth.
    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker), &env.ledger().sequence());
    }

    /// Compute and return rewards for `staker` since last claim. Resets the staked-at ledger.
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

    /// Returns the staked amount for `staker`, defaulting to 0.
    pub fn staked_amount(env: Env, staker: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }

    /// Returns the current reward rate.
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

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};
    use secure::SecureStakingContractClient;

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, StakingContract);
        let admin = Address::generate(&env);
        (env, contract_id, admin)
    }

    #[test]
    fn test_reasonable_rate_works() {
        let (env, contract_id, admin) = setup();
        let client = StakingContractClient::new(&env, &contract_id);
        let staker = Address::generate(&env);

        client.initialize(&admin, &100);
        client.stake(&staker, &1000);

        // Advance ledger so elapsed > 0
        env.ledger().set_sequence_number(10);

        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 1000 * 100 * 10);
        assert_eq!(client.current_rate(), 100);
    }

    /// Demonstrates the vulnerability: admin sets rate to u64::MAX and it is accepted.
    #[test]
    fn test_uncapped_rate_accepted() {
        let (env, contract_id, admin) = setup();
        let client = StakingContractClient::new(&env, &contract_id);
        let staker = Address::generate(&env);

        client.initialize(&admin, &100);
        client.update_rate(&u64::MAX);

        assert_eq!(client.current_rate(), u64::MAX);

        client.stake(&staker, &1);
        env.ledger().set_sequence_number(1);

        // With rate = u64::MAX this will panic on overflow, demonstrating
        // that an uncapped rate lets a malicious admin break rewards.
        let _ = client.claim_rewards(&staker);
    }

    /// Secure version rejects rates above MAX_RATE.
    #[test]
    #[should_panic]
    fn test_secure_rejects_high_rate() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureStakingContract);
        let client = SecureStakingContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &100);
        client.update_rate(&(MAX_RATE + 1));
    }

    /// Secure version accepts a reasonable rate.
    #[test]
    fn test_secure_accepts_reasonable_rate() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureStakingContract);
        let client = SecureStakingContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let staker = Address::generate(&env);

        client.initialize(&admin, &100);
        client.update_rate(&MAX_RATE);
        assert_eq!(client.current_rate(), MAX_RATE);

        client.stake(&staker, &500);
        env.ledger().set_sequence_number(5);

        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 500 * MAX_RATE * 5);
    }
}
