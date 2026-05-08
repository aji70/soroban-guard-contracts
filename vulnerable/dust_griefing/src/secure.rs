#![no_std]
use super::{get_balance, set_balance, MIN_DEPOSIT};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// SECURE: rejects deposits below MIN_DEPOSIT, preventing dust griefing.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ✅ Enforce minimum deposit to prevent storage bloat attacks.
        assert!(amount >= MIN_DEPOSIT, "below minimum deposit");
        let bal = get_balance(&env, &user);
        set_balance(&env, &user, bal + amount);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }
}
