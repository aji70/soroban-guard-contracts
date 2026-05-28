//! VULNERABLE: Epoch Claim Does Not Verify Epoch Has Advanced
//!
//! A reward contract where the claim function pays out the current epoch reward
//! without recording which epoch the user last claimed from. This allows
//! repeated claims within the same epoch.
//!
//! VULNERABILITY: No check that current_epoch > last_claimed_epoch before paying.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    CurrentEpoch,
    RewardPerEpoch,
    LastClaimedEpoch(Address),
}

#[contract]
pub struct RewardVulnerable;

#[contractimpl]
impl RewardVulnerable {
    /// Initialize with current epoch and reward amount.
    pub fn init(env: Env, initial_epoch: u64, reward_per_epoch: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::CurrentEpoch, &initial_epoch);
        env.storage()
            .persistent()
            .set(&DataKey::RewardPerEpoch, &reward_per_epoch);
    }

    /// Advance to the next epoch.
    pub fn advance_epoch(env: Env) {
        let current_epoch: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::CurrentEpoch)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::CurrentEpoch, &(current_epoch + 1));
    }

    /// Get current epoch.
    pub fn current_epoch(env: Env) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::CurrentEpoch)
            .unwrap_or(0)
    }

    /// Get reward amount per epoch.
    pub fn reward_per_epoch(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardPerEpoch)
            .unwrap_or(0)
    }

    /// VULNERABLE: Claim reward without tracking last claimed epoch.
    /// Allows the same user to claim the same epoch reward multiple times.
    pub fn claim_vulnerable(env: Env, _user: Address) -> i128 {
        let reward = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::RewardPerEpoch)
            .unwrap_or(0);

        // ❌ VULNERABLE: no check if the user already claimed this epoch
        // Simply pay the reward without any epoch verification

        // Also no recording of when the user claimed
        reward
    }

    /// Get last claimed epoch for a user (not used in vulnerable path).
    pub fn get_last_claimed_epoch(env: Env, user: Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::LastClaimedEpoch(user))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_vulnerable_duplicate_claim_same_epoch() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardVulnerable);
        let client = RewardVulnerableClient::new(&env, &contract_id);

        // Initialize: epoch 1, reward 100 per epoch
        client.init(&1, &100);

        let user = Address::generate(&env);

        // First claim in epoch 1
        let reward1 = client.claim_vulnerable(&user);
        assert_eq!(reward1, 100);

        // Second claim in same epoch (no epoch advance)
        let reward2 = client.claim_vulnerable(&user);
        assert_eq!(reward2, 100); // ❌ VULNERABLE: gets paid again!

        // The user has claimed twice in the same epoch
        // Total earned: 200, but should have earned 100
    }

    #[test]
    fn test_vulnerable_multiple_claims_before_advance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardVulnerable);
        let client = RewardVulnerableClient::new(&env, &contract_id);

        // Initialize: epoch 0, reward 50 per epoch
        client.init(&0, &50);

        let user = Address::generate(&env);

        // Claim 5 times in epoch 0
        for i in 0..5 {
            let reward = client.claim_vulnerable(&user);
            assert_eq!(reward, 50);
        }

        // Still in epoch 0, but user claimed 5 times
        assert_eq!(client.current_epoch(), 0);

        // User earned 250 instead of 50 (5x the intended reward)
    }

    #[test]
    fn test_vulnerable_boundary_claim_at_epoch_change() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardVulnerable);
        let client = RewardVulnerableClient::new(&env, &contract_id);

        // Initialize: epoch 1, reward 100 per epoch
        client.init(&1, &100);

        let user = Address::generate(&env);

        // Claim once
        let reward1 = client.claim_vulnerable(&user);
        assert_eq!(reward1, 100);

        // Claim again (before epoch advance)
        let reward2 = client.claim_vulnerable(&user);
        assert_eq!(reward2, 100); // Still vulnerable

        // Now advance epoch
        client.advance_epoch();
        assert_eq!(client.current_epoch(), 2);

        // Claim again in new epoch
        let reward3 = client.claim_vulnerable(&user);
        assert_eq!(reward3, 100);

        // But the contract doesn't track which epoch was claimed from
        // so it can't verify the user already claimed from epoch 1
    }
}
