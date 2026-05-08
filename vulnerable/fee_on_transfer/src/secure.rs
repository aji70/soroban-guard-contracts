use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{token, DataKey};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn initialize(env: Env, token: Address) {
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// SECURE: balance-delta pattern — credits only what was actually received.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);

        // ✅ Snapshot balance before transfer.
        let pre_balance = token_client.balance(&env.current_contract_address());

        token_client.transfer(&user, &env.current_contract_address(), &amount);

        // ✅ Measure what was actually received.
        let post_balance = token_client.balance(&env.current_contract_address());
        let actual_received = post_balance - pre_balance;

        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        // ✅ Credit the delta, not the parameter.
        env.storage()
            .persistent()
            .set(&key, &(current + actual_received));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}
