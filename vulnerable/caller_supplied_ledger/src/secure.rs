//! SECURE: Read ledger sequence from `env.ledger().sequence()` instead of
//! trusting caller-supplied values.
//!
//! The secure version removes the `current_ledger` parameter from `withdraw`
//! and reads the ledger sequence directly from the environment. This ensures
//! that time-sensitive checks (cliff, lock, vesting) use the authoritative
//! ledger sequence that cannot be manipulated by the caller.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};
use crate::DataKey;

#[contract]
pub struct SecureVestingContract;

#[contractimpl]
impl SecureVestingContract {
    /// Deposit `amount` with a lock period of `lock_duration` ledger steps and
    /// an optional cliff of `cliff_duration` ledger steps.
    pub fn deposit(
        env: Env,
        user: Address,
        amount: i128,
        lock_duration: u32,
        cliff_duration: u32,
    ) {
        user.require_auth();

        let balance_key = DataKey::Balance(user.clone());
        let current_balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        // ✅ Correctly read deposit ledger from env
        env.storage()
            .persistent()
            .set(&DataKey::DepositLedger(user.clone()), &env.ledger().sequence());

        env.storage()
            .persistent()
            .set(&DataKey::LockDuration(user.clone()), &lock_duration);

        env.storage()
            .persistent()
            .set(&DataKey::CliffDuration(user.clone()), &cliff_duration);

        env.storage()
            .persistent()
            .set(&DataKey::Released(user), &0i128);
    }

    /// ✅ SECURE: No caller-supplied ledger parameter. Reads `env.ledger().sequence()`
    /// directly for all time-sensitive checks.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let balance_key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&balance_key).expect("no balance");

        let deposit_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::DepositLedger(user.clone()))
            .expect("no deposit");

        let lock_duration: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LockDuration(user.clone()))
            .expect("no lock duration");

        let cliff_duration: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::CliffDuration(user.clone()))
            .expect("no cliff duration");

        let released: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Released(user.clone()))
            .unwrap_or(0);

        // ✅ SECURE: Read ledger sequence from the environment — cannot be spoofed.
        let current_ledger = env.ledger().sequence();

        // Cliff check
        if current_ledger < deposit_ledger + cliff_duration {
            panic!("still in cliff period");
        }

        // Lock/vesting check
        let elapsed = current_ledger - deposit_ledger;
        let vested_amount = if elapsed >= lock_duration {
            balance
        } else {
            (i128::from(elapsed) * balance) / i128::from(lock_duration)
        };

        let withdrawable = vested_amount - released;
        if amount > withdrawable {
            panic!("insufficient vested amount");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Released(user.clone()), &(released + amount));

        env.storage()
            .persistent()
            .set(&balance_key, &(balance - amount));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn released(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Released(user))
            .unwrap_or(0)
    }

    pub fn deposit_ledger(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::DepositLedger(user))
    }

    pub fn lock_duration(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::LockDuration(user))
    }

    pub fn cliff_duration(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::CliffDuration(user))
    }
}
