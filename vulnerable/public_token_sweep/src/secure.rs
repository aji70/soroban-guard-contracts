use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureTokenVault;

#[contractimpl]
impl SecureTokenVault {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn deposit(env: Env, depositor: Address, token: Address, amount: i128) {
        depositor.require_auth();
        
        let key = DataKey::TokenBalance(token.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &(current + amount));
    }

    /// SECURE: sweep requires admin authorization before transferring tokens.
    pub fn sweep_tokens(env: Env, token: Address, recipient: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        
        // ✅ Admin must authorize the sweep operation
        admin.require_auth();

        let key = DataKey::TokenBalance(token.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        
        if balance < amount {
            panic!("insufficient balance");
        }

        let new_balance = balance - amount;
        env.storage().persistent().set(&key, &new_balance);

        // In a real implementation, this would call token.transfer()
        // For this fixture, we just track the balance change
    }

    pub fn get_token_balance(env: Env, token: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TokenBalance(token))
            .unwrap_or(0)
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
