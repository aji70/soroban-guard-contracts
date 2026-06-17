//! SECURE: checks both `from` and `to` against the blacklist before transferring.
use crate::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureTokenContract;

#[contractimpl]
impl SecureTokenContract {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn blacklist(env: Env, account: Address) {
        env.storage()
            .persistent()
            .set(&DataKey::Blacklisted(account), &true);
    }

    /// SECURE: checks both `from` and `to` against the blacklist.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        // ✅ Check from against the blacklist.
        if env
            .storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::Blacklisted(from.clone()))
            .unwrap_or(false)
        {
            env.events().publish(
                (symbol_short!("blocked"),),
                (from.clone(), to.clone(), amount),
            );
            panic!("sender is blacklisted");
        }

        if env
            .storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::Blacklisted(to.clone()))
            .unwrap_or(false)
        {
            env.events().publish(
                (symbol_short!("blocked"),),
                (from.clone(), to.clone(), amount),
            );
            panic!("recipient is blacklisted");
        }

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));
        env.storage().persistent().set(&to_key, &(to_bal + amount));

        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}
