//! SECURE: Hook-depth-guarded token.
//!
//! Tracks callback depth in `Temporary` storage. Panics if a hook attempts
//! to re-enter `transfer` beyond `MAX_HOOK_DEPTH` (1 expected level).

#![no_std]
use super::{DataKey, MAX_HOOK_DEPTH};
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum SecureKey {
    HookDepth,
}

#[contract]
pub struct SecureHookedToken;

#[contractimpl]
impl SecureHookedToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// SECURE: increments a `Temporary` depth counter before invoking the
    /// receiver hook and panics if it exceeds `MAX_HOOK_DEPTH`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        // ✅ Read and enforce depth before any external call.
        let depth: u32 = env
            .storage()
            .temporary()
            .get(&SecureKey::HookDepth)
            .unwrap_or(0);
        assert!(depth < MAX_HOOK_DEPTH, "hook depth exceeded");

        let from_key = DataKey::Balance(from.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");

        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));

        let to_key = DataKey::Balance(to.clone());
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&to_key, &(to_bal + amount));

        // Increment depth, fire hook, decrement depth.
        env.storage()
            .temporary()
            .set(&SecureKey::HookDepth, &(depth + 1));

        let _: () = env.invoke_contract(
            &to,
            &symbol_short!("on_xfer"),
            soroban_sdk::vec![&env, from.into_val(&env), amount.into_val(&env)],
        );

        env.storage()
            .temporary()
            .set(&SecureKey::HookDepth, &depth);
    }

    pub fn balance(env: Env, who: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(who))
            .unwrap_or(0)
    }
}
