//! SECURE: Use ledger timestamps for duration-based locks.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};
use super::DataKey;

#[contract]
pub struct SecureSequenceAsTimestampContract;

#[contractimpl]
impl SecureSequenceAsTimestampContract {
    pub fn deposit(env: Env, user: Address, amount: i128, duration_seconds: u32) {
        user.require_auth();

        let balance_key = DataKey::Balance(user.clone());
        let current_balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        let unlock_timestamp = env.ledger().timestamp() + u64::from(duration_seconds);
        env.storage()
            .persistent()
            .set(&DataKey::UnlockSequence(user), &unlock_timestamp);
    }

    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();

        let unlock_timestamp: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::UnlockSequence(user.clone()))
            .expect("unlock not set");

        if env.ledger().timestamp() < unlock_timestamp {
            panic!("still locked");
        }

        env.storage().persistent().set(&DataKey::Balance(user.clone()), &0i128);
        env.storage().persistent().remove(&DataKey::UnlockSequence(user));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn unlock_timestamp(env: Env, user: Address) -> Option<u64> {
        env.storage().persistent().get(&DataKey::UnlockSequence(user))
    }
}
