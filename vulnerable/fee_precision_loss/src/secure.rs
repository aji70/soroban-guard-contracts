#![no_std]
use super::{balance_of, fees_collected, BPS_DENOM, FEE_BPS, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureFeeContract;

#[contractimpl]
impl SecureFeeContract {
    pub fn mint(env: Env, user: Address, amount: i128) {
        assert!(amount > 0);
        let bal = balance_of(&env, &user);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &(bal + amount));
    }

    /// SECURE: enforces a minimum fee of 1 when a nonzero rate applies.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        assert!(amount > 0, "amount must be positive");

        let raw_fee = amount * FEE_BPS / BPS_DENOM;
        // ✅ Minimum fee of 1 prevents dust-split fee bypass.
        let fee = if raw_fee == 0 && FEE_BPS > 0 { 1 } else { raw_fee };

        let from_bal = balance_of(&env, &from);
        assert!(from_bal >= amount, "insufficient balance");

        env.storage()
            .persistent()
            .set(&DataKey::Balance(from), &(from_bal - amount));

        let to_bal = balance_of(&env, &to);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to), &(to_bal + amount - fee));

        let collected = fees_collected(&env);
        env.storage()
            .persistent()
            .set(&DataKey::FeesCollected, &(collected + fee));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        balance_of(&env, &user)
    }

    pub fn fees_collected(env: Env) -> i128 {
        fees_collected(&env)
    }
}
