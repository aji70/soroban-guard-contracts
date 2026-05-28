//! SECURE mirror: Burn wrapper shares before transferring underlying tokens.
//!
//! Key fix:
//! - Decrement wrapper balance and total supply BEFORE transferring underlying tokens
//! - This prevents users from unwrapping the same shares multiple times

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct SecureWrapper;

#[contractimpl]
impl SecureWrapper {
    pub fn initialize(env: Env, underlying_token: Address) {
        if env.storage().persistent().has(&DataKey::UnderlyingToken) {
            panic!("already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::UnderlyingToken, &underlying_token);
        env.storage().persistent().set(&DataKey::TotalSupply, &0i128);
        env.storage().persistent().set(&DataKey::CustodyBalance, &0i128);
    }

    pub fn wrap(env: Env, user: Address, amount: i128) {
        user.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let underlying_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::UnderlyingToken)
            .expect("not initialized");

        let token_client = token::TokenClient::new(&env, &underlying_token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        let balance_key = DataKey::WrapperBalance(user.clone());
        let current_balance: i128 = env
            .storage()
            .persistent()
            .get(&balance_key)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        let total_supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total_supply + amount));

        let custody: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CustodyBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::CustodyBalance, &(custody + amount));
    }

    /// ✅ Fixed: Burns wrapper shares BEFORE transferring underlying tokens.
    pub fn unwrap(env: Env, user: Address, amount: i128) {
        user.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let balance_key = DataKey::WrapperBalance(user.clone());
        let current_balance: i128 = env
            .storage()
            .persistent()
            .get(&balance_key)
            .unwrap_or(0);

        if current_balance < amount {
            panic!("insufficient wrapper balance");
        }

        let custody: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CustodyBalance)
            .unwrap_or(0);

        if custody < amount {
            panic!("insufficient custody balance");
        }

        // ✅ Burn wrapper shares FIRST (checks-effects-interactions pattern)
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance - amount));

        let total_supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total_supply - amount));

        // Update custody balance
        env.storage()
            .persistent()
            .set(&DataKey::CustodyBalance, &(custody - amount));

        // Transfer underlying tokens AFTER burning shares
        let underlying_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::UnderlyingToken)
            .expect("not initialized");

        let token_client = token::TokenClient::new(&env, &underlying_token);
        token_client.transfer(&env.current_contract_address(), &user, &amount);
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::WrapperBalance(user))
            .unwrap_or(0)
    }

    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    pub fn custody_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CustodyBalance)
            .unwrap_or(0)
    }
}
