use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{get_rate, get_stake, get_staked_at, set_stake, set_staked_at};

#[contract]
pub struct SecureStake;

#[contractimpl]
impl SecureStake {
    pub fn initialize(env: Env, reward_rate: i128) {
        env.storage()
            .persistent()
            .set(&super::DataKey::RewardRate, &reward_rate);
    }

    /// SECURE: rejects the contract's own address as a staker, preventing
    /// circular balance entries that distort total-supply calculations.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ✅ Guard against self-staking.
        if staker == env.current_contract_address() {
            panic!("contract cannot stake to itself");
        }
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let current = get_stake(&env, &staker);
        set_stake(&env, &staker, current + amount);
        set_staked_at(&env, &staker, env.ledger().sequence());
    }

    /// SECURE: same guard applied to unstake.
    pub fn unstake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ✅ Guard against self-staking.
        if staker == env.current_contract_address() {
            panic!("contract cannot stake to itself");
        }
        let current = get_stake(&env, &staker);
        let new_balance = current.checked_sub(amount).expect("insufficient stake");
        set_stake(&env, &staker, new_balance);
    }

    /// SECURE: same guard applied to claim_rewards.
    pub fn claim_rewards(env: Env, staker: Address) -> i128 {
        staker.require_auth();
        // ✅ Guard against self-staking.
        if staker == env.current_contract_address() {
            panic!("contract cannot stake to itself");
        }
        let elapsed = (env.ledger().sequence() - get_staked_at(&env, &staker)) as i128;
        let reward = get_stake(&env, &staker)
            .checked_mul(get_rate(&env))
            .and_then(|v| v.checked_mul(elapsed))
            .unwrap_or(0);
        set_staked_at(&env, &staker, env.ledger().sequence());
        reward
    }

    pub fn get_stake(env: Env, staker: Address) -> i128 {
        get_stake(&env, &staker)
    }
}
