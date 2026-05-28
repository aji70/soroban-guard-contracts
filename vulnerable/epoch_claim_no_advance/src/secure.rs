//! SECURE: Epoch Claim Verifies Epoch Has Advanced
//!
//! Fixed version that stores last_claimed_epoch per user and requires
//! current_epoch > last_claimed_epoch before paying. Rejects duplicate
//! claims in the same epoch.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    CurrentEpoch,
    RewardPerEpoch,
    LastClaimedEpoch(Address),
}

#[contract]
pub struct RewardSecure;

#[contractimpl]
impl RewardSecure {
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

    /// ✓ FIXED: Claim reward and verify epoch has advanced.
    /// Stores last_claimed_epoch and requires current_epoch > last_claimed_epoch.
    pub fn claim_secure(env: Env, user: Address) -> i128 {
        let current = env
            .storage()
            .persistent()
            .get::<_, u64>(&DataKey::CurrentEpoch)
            .unwrap_or(0);

        let last_claimed: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::LastClaimedEpoch(user.clone()))
            .unwrap_or(0);

        // ✓ FIXED: verify epoch has advanced
        assert!(
            current > last_claimed,
            "User already claimed reward for this epoch"
        );

        let reward = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::RewardPerEpoch)
            .unwrap_or(0);

        // ✓ FIXED: record that user claimed in this epoch
        env.storage()
            .persistent()
            .set(&DataKey::LastClaimedEpoch(user), &current);

        reward
    }

    /// Get last claimed epoch for a user.
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
    #[should_panic(expected = "User already claimed reward for this epoch")]
    fn test_secure_rejects_duplicate_claim_same_epoch() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardSecure);
        let client = RewardSecureClient::new(&env, &contract_id);

        // Initialize: epoch 1, reward 100 per epoch
        client.init(&1, &100);

        let user = Address::generate(&env);

        // First claim in epoch 1
        let reward1 = client.claim_secure(&user);
        assert_eq!(reward1, 100);
        assert_eq!(client.get_last_claimed_epoch(&user), 1);

        // Second claim in same epoch — should panic
        client.claim_secure(&user);
    }

    #[test]
    fn test_secure_allows_claim_after_epoch_advance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardSecure);
        let client = RewardSecureClient::new(&env, &contract_id);

        // Initialize: epoch 1, reward 100 per epoch
        client.init(&1, &100);

        let user = Address::generate(&env);

        // First claim in epoch 1
        let reward1 = client.claim_secure(&user);
        assert_eq!(reward1, 100);
        assert_eq!(client.get_last_claimed_epoch(&user), 1);

        // Advance epoch to 2
        client.advance_epoch();

        // Claim in epoch 2 — should succeed
        let reward2 = client.claim_secure(&user);
        assert_eq!(reward2, 100);
        assert_eq!(client.get_last_claimed_epoch(&user), 2);
    }

    #[test]
    fn test_secure_tracks_claim_state_per_user() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardSecure);
        let client = RewardSecureClient::new(&env, &contract_id);

        // Initialize: epoch 1, reward 100 per epoch
        client.init(&1, &100);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        // Alice claims in epoch 1
        let reward_alice_1 = client.claim_secure(&alice);
        assert_eq!(reward_alice_1, 100);

        // Bob claims in epoch 1 (different user, so allowed)
        let reward_bob_1 = client.claim_secure(&bob);
        assert_eq!(reward_bob_1, 100);

        // Advance epoch
        client.advance_epoch();

        // Alice can claim again in epoch 2
        let reward_alice_2 = client.claim_secure(&alice);
        assert_eq!(reward_alice_2, 100);

        // Bob can claim again in epoch 2
        let reward_bob_2 = client.claim_secure(&bob);
        assert_eq!(reward_bob_2, 100);

        // Verify tracking
        assert_eq!(client.get_last_claimed_epoch(&alice), 2);
        assert_eq!(client.get_last_claimed_epoch(&bob), 2);
    }

    #[test]
    fn test_secure_initial_claim_first_epoch() {
        let env = Env::default();
        let contract_id = env.register_contract(None, RewardSecure);
        let client = RewardSecureClient::new(&env, &contract_id);

        // Initialize: epoch 1, reward 50 per epoch
        // (epochs should start at 1 to work with last_claimed defaulting to 0)
        client.init(&1, &50);

        let user = Address::generate(&env);

        // First claim in epoch 1 (last_claimed defaults to 0)
        // current (1) > last_claimed (0)? Yes, allowed
        let reward = client.claim_secure(&user);
        assert_eq!(reward, 50);
        assert_eq!(client.get_last_claimed_epoch(&user), 1);
    }
}
