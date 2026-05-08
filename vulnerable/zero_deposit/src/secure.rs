use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// SECURE: rejects zero (and negative) deposits before touching storage.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ✅ Guard ensures no empty or negative entries are ever written.
        assert!(amount > 0, "deposit must be positive");
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}
