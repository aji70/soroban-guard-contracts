use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// SECURE: the user must explicitly authorise their own withdrawal.
    /// A malicious intermediary cannot forge this signature.
    pub fn withdraw(env: Env, user: Address, amount: i128) -> i128 {
        // ✅ Explicit user auth — intermediary contracts cannot impersonate.
        user.require_auth();

        let key = DataKey::Balance(user.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_bal = bal.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_bal);
        amount
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}
