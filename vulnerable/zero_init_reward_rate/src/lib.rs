//! # zero_init_reward_rate
//!
//! **Vulnerability (High):** The staking contract's `initialize` function
//! accepts `reward_rate = 0` without complaint. Once initialized with a zero
//! rate, `claim_rewards` always returns 0 for every staker regardless of stake
//! size or duration. There is no admin function to update the rate
//! post-initialization, making the broken state permanent.
//!
//! **Fix:** Reject `reward_rate == 0` at initialization time.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    RewardRate,
    Stake(Address),
    LastClaim(Address),
}

#[contract]
pub struct StakingContract;

#[contractimpl]
impl StakingContract {
    // ── VULNERABLE initialize ────────────────────────────────────────────────

    /// Initialize the staking contract.
    ///
    /// **BUG:** accepts `reward_rate = 0`, permanently breaking reward payouts.
    pub fn initialize_vulnerable(env: Env, admin: Address, reward_rate: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        // BUG: zero reward_rate accepted — staking permanently yields nothing
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    // ── FIXED initialize ─────────────────────────────────────────────────────

    /// Initialize the staking contract.
    ///
    /// **FIX:** panics if `reward_rate` is zero.
    pub fn initialize(env: Env, admin: Address, reward_rate: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        if reward_rate == 0 {
            panic!("reward_rate cannot be zero at initialization");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    // ── Staking ──────────────────────────────────────────────────────────────

    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(staker.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Stake(staker.clone()), &(current + amount));
        env.storage()
            .persistent()
            .set(&DataKey::LastClaim(staker), &env.ledger().timestamp());
    }

    /// Claim rewards: reward = stake * rate * elapsed_seconds.
    pub fn claim_rewards(env: Env, staker: Address) -> i128 {
        staker.require_auth();
        let stake: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(staker.clone()))
            .unwrap_or(0);
        let rate: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0);
        let last: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::LastClaim(staker.clone()))
            .unwrap_or(env.ledger().timestamp());
        let elapsed = (env.ledger().timestamp() - last) as i128;
        let reward = stake * rate * elapsed;
        env.storage()
            .persistent()
            .set(&DataKey::LastClaim(staker), &env.ledger().timestamp());
        reward
    }

    pub fn get_reward_rate(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn make_env() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let staker = Address::generate(&env);
        (env, admin, staker)
    }

    /// BUG DEMO: zero reward_rate is accepted and claim_rewards always returns 0.
    #[test]
    fn test_zero_rate_accepted_and_yields_nothing() {
        let (env, admin, staker) = make_env();
        let id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &id);

        client.initialize_vulnerable(&admin, &0);
        assert_eq!(client.get_reward_rate(), 0);

        client.stake(&staker, &1_000_000);
        // Advance time
        env.ledger().with_mut(|l| l.timestamp += 3600);
        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 0); // always zero — bug demonstrated
    }

    /// FIX: initializing with reward_rate = 0 now panics.
    #[test]
    #[should_panic(expected = "reward_rate cannot be zero at initialization")]
    fn test_zero_rate_rejected_by_fix() {
        let (env, admin, _staker) = make_env();
        let id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &id);
        client.initialize(&admin, &0);
    }

    /// A valid positive reward rate is stored and used correctly.
    #[test]
    fn test_positive_rate_yields_correct_rewards() {
        let (env, admin, staker) = make_env();
        let id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &id);

        client.initialize(&admin, &10); // rate = 10
        client.stake(&staker, &100);    // stake = 100

        env.ledger().with_mut(|l| l.timestamp += 5); // elapsed = 5s
        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 100 * 10 * 5); // 5000
    }
}
