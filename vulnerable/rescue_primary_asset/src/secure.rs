use super::DataKey;
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn initialize(env: Env, admin: Address, managed_token: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ManagedToken, &managed_token);
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let managed_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .expect("not initialized");

        let token_client = token::Client::new(&env, &managed_token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);

        let managed_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .unwrap();

        let token_client = token::Client::new(&env, &managed_token);
        token_client.transfer(&env.current_contract_address(), &user, &amount);
    }

    /// SECURE: rescue any token EXCEPT the managed token.
    /// Explicitly blocks rescue of the primary protocol asset.
    pub fn rescue_token(env: Env, token: Address, recipient: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let managed_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .unwrap();

        // ✅ Block rescue of the managed token
        if token == managed_token {
            panic!("cannot rescue managed token");
        }

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &recipient, &amount);
    }

    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn get_managed_token(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .expect("not initialized")
    }
}
