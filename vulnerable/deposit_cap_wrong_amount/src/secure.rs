//! SECURE: apply the deposit cap to the post-transfer credited delta.

use super::{token, DataKey, DEPOSIT_CAP};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureDepositCap;

#[contractimpl]
impl SecureDepositCap {
    pub fn initialize(env: Env, token: Address) {
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// SECURE: measure received tokens, then enforce the cap on credited totals.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);
        let vault = env.current_contract_address();
        let pre = token_client.balance(&vault);

        token_client.transfer(&user, &vault, &amount);

        let post = token_client.balance(&vault);
        let received = post - pre;

        let total: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalCredited)
            .unwrap_or(0);

        assert!(total + received <= DEPOSIT_CAP, "deposit cap exceeded");

        env.storage()
            .persistent()
            .set(&DataKey::TotalCredited, &(total + received));
    }

    pub fn total_credited(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalCredited)
            .unwrap_or(0)
    }
}
