#![no_std]
use super::{DataKey, NotifyContractClient};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureReentrantVault;

#[contractimpl]
impl SecureReentrantVault {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn withdraw(env: Env, user: Address, amount: i128, notify_id: Address) {
        user.require_auth();

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(user.clone()))
            .unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");

        // ✅ SECURE: Update state before making the external call.
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user.clone()), &new_balance);

        NotifyContractClient::new(&env, &notify_id).on_withdraw(&user, &amount);

        let withdrawn_key = DataKey::Withdrawn(user.clone());
        let withdrawn: i128 = env.storage().persistent().get(&withdrawn_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&withdrawn_key, &(withdrawn + amount));
    }

    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn get_withdrawn(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Withdrawn(user))
            .unwrap_or(0)
    }
}
