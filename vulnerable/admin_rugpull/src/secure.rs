use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureEscrow;

#[contractimpl]
impl SecureEscrow {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
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
    }

    /// SECURE: both admin AND user must authorise a forced withdrawal.
    pub fn admin_withdraw(env: Env, user: Address, recipient: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        // ✅ User must co-sign — admin cannot act unilaterally.
        user.require_auth();

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);

        let recipient_key = DataKey::Balance(recipient.clone());
        let recipient_bal: i128 = env.storage().persistent().get(&recipient_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&recipient_key, &(recipient_bal + amount));
    }

    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}
