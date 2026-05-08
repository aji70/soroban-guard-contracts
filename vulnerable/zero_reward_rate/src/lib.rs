//! # zero_reward_rate
//!
//! **Vulnerability (Medium):** The staking contract lets the admin set the
//! reward rate to `0`. Once that happens, `claim_rewards` quietly returns `0`
//! for everyone, so stakers have no on-chain signal that rewards have been
//! disabled.
//!
//! **Fix:** Reject a zero reward rate and emit a `RewardRateChanged` event
//! whenever the rate changes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    RewardRate,
    Stake(Address),
    StakedAt(Address),
}

#[contract]
pub struct StakingContract;

#[contractimpl]
impl StakingContract {
    pub fn initialize(env: Env, admin: Address, reward_rate: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    /// Vulnerable version: accepts a zero reward rate silently.
    pub fn set_reward_rate(env: Env, rate: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::RewardRate, &rate);
    }

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
            .set(&DataKey::StakedAt(staker), &env.ledger().timestamp());
    }

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
            .get(&DataKey::StakedAt(staker.clone()))
            .unwrap_or(env.ledger().timestamp());
        let elapsed = (env.ledger().timestamp() - last) as i128;
        let reward = stake * rate * elapsed;
        env.storage()
            .persistent()
            .set(&DataKey::StakedAt(staker), &env.ledger().timestamp());
        reward
    }

    pub fn get_reward_rate(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0)
    }
}

pub mod secure {
    use super::DataKey;
    use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

    #[contract]
    pub struct SecureStakingContract;

    #[contractimpl]
    impl SecureStakingContract {
        pub fn initialize(env: Env, admin: Address, reward_rate: i128) {
            if env.storage().persistent().has(&DataKey::Admin) {
                panic!("already initialized");
            }
            if reward_rate == 0 {
                panic!("reward rate cannot be zero");
            }
            env.storage().persistent().set(&DataKey::Admin, &admin);
            env.storage()
                .persistent()
                .set(&DataKey::RewardRate, &reward_rate);
        }

        pub fn set_reward_rate(env: Env, rate: i128) {
            let admin: Address = env
                .storage()
                .persistent()
                .get(&DataKey::Admin)
                .expect("not initialized");
            admin.require_auth();
            if rate == 0 {
                panic!("reward rate cannot be zero");
            }

            let old_rate: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::RewardRate)
                .unwrap_or(0);

            env.storage().persistent().set(&DataKey::RewardRate, &rate);
            env.events()
                .publish((Symbol::new(&env, "RewardRateChanged"),), (old_rate, rate));
        }

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
                .set(&DataKey::StakedAt(staker), &env.ledger().timestamp());
        }

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
                .get(&DataKey::StakedAt(staker.clone()))
                .unwrap_or(env.ledger().timestamp());
            let elapsed = (env.ledger().timestamp() - last) as i128;
            let reward = stake * rate * elapsed;
            env.storage()
                .persistent()
                .set(&DataKey::StakedAt(staker), &env.ledger().timestamp());
            reward
        }

        pub fn get_reward_rate(env: Env) -> i128 {
            env.storage()
                .persistent()
                .get(&DataKey::RewardRate)
                .unwrap_or(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events as _, Ledger as _},
        Address, Env, Symbol, TryFromVal, Val, Vec,
    };

    fn setup(rate: i128) -> (Env, Address, StakingContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, StakingContract);
        let client = StakingContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &rate);
        (env, admin, client)
    }

    #[test]
    fn test_vulnerable_zero_rate_accepted_and_claim_rewards_returns_zero() {
        let (env, _admin, client) = setup(10);
        let staker = Address::generate(&env);

        client.set_reward_rate(&0);
        assert_eq!(client.get_reward_rate(), 0);

        env.ledger().set_timestamp(100);
        client.stake(&staker, &1_000);
        env.ledger().set_timestamp(160);

        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 0);
    }

    #[test]
    #[should_panic(expected = "reward rate cannot be zero")]
    fn test_secure_rejects_zero_reward_rate() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStakingContract);
        let client = secure::SecureStakingContractClient::new(&env, &id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &10);
        client.set_reward_rate(&0);
    }

    #[test]
    fn test_secure_accepts_rate_and_emits_event() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStakingContract);
        let client = secure::SecureStakingContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        let staker = Address::generate(&env);
        client.initialize(&admin, &10);

        client.set_reward_rate(&25);
        assert_eq!(client.get_reward_rate(), 25);

        let events = env.events().all();
        assert_eq!(
            events.len(),
            1,
            "expected exactly one RewardRateChanged event"
        );

        let (_, topics, data) = events.last().unwrap();
        let topic_vec = Vec::<Val>::try_from_val(&env, &topics).unwrap();
        let topic_sym = Symbol::try_from_val(&env, &topic_vec.get(0).unwrap()).unwrap();
        assert_eq!(topic_sym, Symbol::new(&env, "RewardRateChanged"));

        let data_vec = Vec::<Val>::try_from_val(&env, &data).unwrap();
        let old_rate = i128::try_from_val(&env, &data_vec.get(0).unwrap()).unwrap();
        let new_rate = i128::try_from_val(&env, &data_vec.get(1).unwrap()).unwrap();
        assert_eq!(old_rate, 10);
        assert_eq!(new_rate, 25);

        env.ledger().set_timestamp(200);
        client.stake(&staker, &1_000);
        env.ledger().set_timestamp(260);

        let reward = client.claim_rewards(&staker);
        assert_eq!(reward, 1_000 * 25 * 60);
    }
}
