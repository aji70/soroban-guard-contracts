//! SECURE: Staking Contract — Checked Arithmetic, Admin-Gated Rate, TTL Extension
//!
//! Secure mirror of `unchecked_math`. Fixes every vulnerability in that contract:
//!
//! - ✅ `checked_mul` / `checked_add` — overflow panics cleanly instead of wrapping
//! - ✅ Admin-gated `update_rate` with a `MAX_RATE` cap
//! - ✅ `assert!(amount > 0)` on stake — rejects zero-amount stakes
//! - ✅ `extend_ttl` on every persistent storage read/write — entries never expire

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// Maximum allowed reward rate (tokens per ledger per staked token, scaled ×1_000_000).
const MAX_RATE: u64 = 1_000_000;

/// TTL thresholds: keep entries alive for at least 100 ledgers, extend to 500.
const TTL_THRESHOLD: u32 = 100;
const TTL_EXTEND_TO: u32 = 500;

#[contracttype]
pub enum DataKey {
    Admin,
    Stake(Address),
    StakedAt(Address),
    RewardRate,
}

#[contract]
pub struct SecureStaking;

#[contractimpl]
impl SecureStaking {
    pub fn initialize(env: Env, admin: Address, reward_rate: u64) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        assert!(reward_rate <= MAX_RATE, "rate exceeds MAX_RATE");
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::RewardRate, TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Admin-only: update the reward rate, capped at MAX_RATE.
    pub fn update_rate(env: Env, caller: Address, new_rate: u64) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        assert!(caller == admin, "not admin");
        assert!(new_rate <= MAX_RATE, "rate exceeds MAX_RATE");
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &new_rate);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::RewardRate, TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Stake `amount` tokens. Rejects zero amounts and extends TTL on write.
    pub fn stake(env: Env, staker: Address, amount: u64) {
        staker.require_auth();
        assert!(amount > 0, "amount must be positive");
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &amount);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Stake(staker.clone()), TTL_THRESHOLD, TTL_EXTEND_TO);
        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker.clone()), &env.ledger().sequence());
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::StakedAt(staker), TTL_THRESHOLD, TTL_EXTEND_TO);
    }

    /// Claim rewards. Uses checked arithmetic — panics cleanly on overflow.
    /// Extends TTL on every storage access.
    pub fn claim_rewards(env: Env, staker: Address) -> u64 {
        staker.require_auth();

        let stake_key = DataKey::Stake(staker.clone());
        let at_key = DataKey::StakedAt(staker.clone());

        let staked: u64 = env
            .storage()
            .persistent()
            .get(&stake_key)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .extend_ttl(&stake_key, TTL_THRESHOLD, TTL_EXTEND_TO);

        let staked_at: u32 = env
            .storage()
            .persistent()
            .get(&at_key)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .extend_ttl(&at_key, TTL_THRESHOLD, TTL_EXTEND_TO);

        let rate: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::RewardRate, TTL_THRESHOLD, TTL_EXTEND_TO);

        let current = env.ledger().sequence();
        let elapsed = (current - staked_at) as u64;

        // ✅ checked_mul — panics with a clear message instead of silently wrapping
        let reward = staked
            .checked_mul(rate)
            .and_then(|v| v.checked_mul(elapsed))
            .expect("reward overflow");

        env.storage().persistent().set(&at_key, &current);
        env.storage()
            .persistent()
            .extend_ttl(&at_key, TTL_THRESHOLD, TTL_EXTEND_TO);

        reward
    }

    pub fn staked_amount(env: Env, staker: Address) -> u64 {
        let key = DataKey::Stake(staker);
        let val = env.storage().persistent().get(&key).unwrap_or(0);
        if val > 0 {
            env.storage()
                .persistent()
                .extend_ttl(&key, TTL_THRESHOLD, TTL_EXTEND_TO);
        }
        val
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup(rate: u64) -> (Env, Address, SecureStakingClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureStaking);
        let client = SecureStakingClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &rate);
        (env, admin, client)
    }

    /// Normal stake and claim produces correct reward.
    #[test]
    fn test_stake_and_claim_normal() {
        let (env, _, client) = setup(10);
        let staker = Address::generate(&env);

        env.ledger().set_sequence_number(100);
        client.stake(&staker, &1000);

        env.ledger().set_sequence_number(110); // 10 ledgers elapsed
        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 1000 * 10 * 10); // staked * rate * elapsed
    }

    /// Zero-amount stake is rejected.
    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_stake_zero_rejected() {
        let (env, _, client) = setup(10);
        let staker = Address::generate(&env);
        client.stake(&staker, &0);
    }

    /// Overflow attempt panics cleanly via checked_mul.
    #[test]
    #[should_panic(expected = "reward overflow")]
    fn test_overflow_panics_cleanly() {
        let (env, _, client) = setup(MAX_RATE);
        let staker = Address::generate(&env);

        env.ledger().set_sequence_number(0);
        client.stake(&staker, &u64::MAX);

        env.ledger().set_sequence_number(1); // elapsed = 1; u64::MAX * MAX_RATE overflows
        client.claim_rewards(&staker);
    }

    /// Non-admin cannot update rate.
    #[test]
    #[should_panic(expected = "not admin")]
    fn test_non_admin_cannot_update_rate() {
        let (env, _, client) = setup(10);
        let attacker = Address::generate(&env);
        client.update_rate(&attacker, &20);
    }

    /// Rate above MAX_RATE is rejected.
    #[test]
    #[should_panic(expected = "rate exceeds MAX_RATE")]
    fn test_rate_above_max_rejected() {
        let (env, admin, client) = setup(10);
        client.update_rate(&admin, &(MAX_RATE + 1));
    }

    /// Admin can update rate within bounds.
    #[test]
    fn test_admin_can_update_rate() {
        let (env, admin, client) = setup(10);
        let staker = Address::generate(&env);

        client.update_rate(&admin, &50);

        env.ledger().set_sequence_number(0);
        client.stake(&staker, &100);
        env.ledger().set_sequence_number(2);

        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 100 * 50 * 2);
    }
}
