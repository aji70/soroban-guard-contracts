//! SECURE: Atomic batch executor — panics on the first failing operation,
//! causing the Soroban host to revert all state changes for the transaction.

#![no_std]
use super::{DataKey, Transfer};
use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct SecureBatchExecutor;

#[contractimpl]
impl SecureBatchExecutor {
    pub fn mint(env: Env, to: soroban_sdk::Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// SECURE: panics on the first insufficient-balance operation, reverting
    /// all state changes atomically via the Soroban host.
    pub fn execute_batch(env: Env, ops: Vec<Transfer>) {
        for op in ops.iter() {
            let from_key = DataKey::Balance(op.from.clone());
            let from_bal: i128 = env
                .storage()
                .persistent()
                .get(&from_key)
                .unwrap_or(0);

            // ✅ Panic on failure — host reverts the entire transaction.
            assert!(from_bal >= op.amount, "insufficient balance in batch");

            env.storage()
                .persistent()
                .set(&from_key, &(from_bal - op.amount));

            let to_key = DataKey::Balance(op.to.clone());
            let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
            env.storage()
                .persistent()
                .set(&to_key, &(to_bal + op.amount));
        }
    }

    pub fn balance(env: Env, who: soroban_sdk::Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(who))
            .unwrap_or(0)
    }
}
