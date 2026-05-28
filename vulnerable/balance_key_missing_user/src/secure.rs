//! SECURE: Include the user identity in balance storage keys.
#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};
use super::DataKey;

#[contract]
pub struct SecureBalanceKeyMissingUserContract;

#[contractimpl]
impl SecureBalanceKeyMissingUserContract {
    pub fn deposit(env: Env, user: Address, asset: Symbol, amount: i128) {
        user.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::UserBalance(asset, user), &amount);
    }

    pub fn balance(env: Env, user: Address, asset: Symbol) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::UserBalance(asset, user))
            .unwrap_or(0)
    }
}
