//! SECURE mirror: enforce a minimum ledger delay between price update and consumption.
//!
//! `get_price` panics if the current ledger sequence is within `delay` ledgers
//! of the last `set_price` call, preventing same-ledger flash-loan manipulation.

use crate::{get_admin, DataKey};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
enum SecureKey {
    Delay,
}

#[contract]
pub struct SecureOracle;

#[contractimpl]
impl SecureOracle {
    pub fn initialize(env: Env, admin: Address, delay: u32) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&SecureKey::Delay, &delay);
    }

    pub fn set_price(env: Env, price: i128) {
        let admin = get_admin(&env);
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Price, &price);
        let seq = env.ledger().sequence();
        env.storage().persistent().set(&DataKey::UpdatedAt, &seq);
    }

    /// ✅ Rejects reads until at least `delay` ledgers have passed since the last update.
    pub fn get_price(env: Env) -> i128 {
        let updated_at: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::UpdatedAt)
            .unwrap_or(0);
        let delay: u32 = env
            .storage()
            .persistent()
            .get(&SecureKey::Delay)
            .unwrap_or(0);
        if env.ledger().sequence() <= updated_at + delay {
            panic!("price not yet valid");
        }
        env.storage().persistent().get(&DataKey::Price).unwrap_or(0)
    }
}
