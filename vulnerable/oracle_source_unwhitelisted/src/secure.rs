//! SECURE mirror: store a whitelisted oracle address at initialisation time
//! and reject any `update_price` call whose `oracle` argument does not match.
//!
//! ✅ FIX: `update_price` compares the caller-supplied `oracle` against the
//! address stored under `DataKey::Oracle` and panics with
//! "oracle not whitelisted" if they differ.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contracttype]
pub enum SecureKey {
    Oracle,
}

#[contract]
pub struct SecurePriceConsumer;

#[contractimpl]
impl SecurePriceConsumer {
    /// Initialise with both an admin and the single trusted oracle address.
    pub fn initialize(env: Env, admin: Address, oracle: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&SecureKey::Oracle, &oracle);
    }

    /// ✅ SECURE: rejects any oracle address that is not the stored whitelist entry.
    pub fn update_price(env: Env, actor: Address, oracle: Address, price: i128) {
        actor.require_auth();

        let allowed: Address = env
            .storage()
            .instance()
            .get(&SecureKey::Oracle)
            .expect("not initialized");

        // ✅ Reject caller-supplied oracle if it does not match the stored one
        if oracle != allowed {
            panic!("oracle not whitelisted");
        }

        env.storage().instance().set(&DataKey::Price, &price);
    }

    pub fn get_price(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Price)
            .unwrap_or(0)
    }

    /// Expose the stored oracle address (useful in tests).
    pub fn oracle(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&SecureKey::Oracle)
            .expect("not initialized")
    }
}
