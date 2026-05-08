use super::{DataKey, MIN_STAKE};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureStaking;

#[contractimpl]
impl SecureStaking {
    /// Initialize the contract with an admin and a configurable minimum stake.
    ///
    /// The admin chooses the threshold, but it cannot be lower than the
    /// repository default `MIN_STAKE`.
    pub fn initialize(env: Env, admin: Address, min_stake: i128) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        admin.require_auth();
        assert!(min_stake >= MIN_STAKE, "minimum stake below default");

        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::MinStake, &min_stake);
    }

    /// SECURE: rejects amounts below the configured minimum stake.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        let min_stake: i128 = env
            .storage()
            .instance()
            .get(&DataKey::MinStake)
            .unwrap_or(MIN_STAKE);
        assert!(amount >= min_stake, "stake below minimum");

        let key = DataKey::Stake(staker.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn balance(env: Env, staker: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }
}
