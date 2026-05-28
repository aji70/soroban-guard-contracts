#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    RewardRate,
    Debt(Address),
    RewardCheckpoint(Address),
    AccruedReward(Address),
}

#[contract]
pub struct SecureRepayForRewardGrief;

#[contractimpl]
impl SecureRepayForRewardGrief {
    pub fn initialize(env: Env, admin: Address, reward_rate: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        if reward_rate <= 0 {
            panic!("reward_rate must be positive");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Debt(borrower.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
        env.storage()
            .persistent()
            .set(&DataKey::RewardCheckpoint(borrower), &env.ledger().timestamp());
    }

    pub fn repay_for(env: Env, payer: Address, borrower: Address, amount: i128) {
        payer.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        let debt = Self::get_debt(&env, &borrower);
        if amount > debt {
            panic!("repay amount exceeds debt");
        }

        let checkpoint = Self::get_reward_checkpoint(&env, &borrower);
        let elapsed = (env.ledger().timestamp() - checkpoint) as i128;
        let reward_rate = Self::get_reward_rate(&env);
        let accrued: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AccruedReward(borrower.clone()))
            .unwrap_or(0);
        let vested = accrued + debt * reward_rate * elapsed;

        env.storage()
            .persistent()
            .set(&DataKey::AccruedReward(borrower.clone()), &vested);
        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower.clone()), &(debt - amount));
        env.storage()
            .persistent()
            .set(&DataKey::RewardCheckpoint(borrower), &env.ledger().timestamp());
    }

    pub fn claim_rewards(env: Env, borrower: Address) -> i128 {
        borrower.require_auth();
        let debt = Self::get_debt(&env, &borrower);
        let reward_rate = Self::get_reward_rate(&env);
        let checkpoint = Self::get_reward_checkpoint(&env, &borrower);
        let elapsed = (env.ledger().timestamp() - checkpoint) as i128;
        let accrued: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AccruedReward(borrower.clone()))
            .unwrap_or(0);
        let reward = accrued + debt * reward_rate * elapsed;
        env.storage()
            .persistent()
            .set(&DataKey::AccruedReward(borrower), &0i128);
        env.storage()
            .persistent()
            .set(&DataKey::RewardCheckpoint(borrower), &env.ledger().timestamp());
        reward
    }

    fn get_debt(env: &Env, borrower: &Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Debt(borrower.clone()))
            .unwrap_or(0)
    }

    fn get_reward_rate(env: &Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0)
    }

    fn get_reward_checkpoint(env: &Env, borrower: &Address) -> u64 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardCheckpoint(borrower.clone()))
            .unwrap_or(env.ledger().timestamp())
    }
}
