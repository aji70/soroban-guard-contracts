//! SECURE: Event authority derived from the authenticated signer only.
//! No caller-supplied authority argument is accepted.

#![no_std]
use super::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureContract;

#[contractimpl]
impl SecureContract {
    pub fn init(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: `actor` must authenticate; the event authority is `actor` —
    /// no untrusted argument can influence what is emitted.
    pub fn execute(env: Env, actor: Address, amount: i128) {
        actor.require_auth();

        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ActionCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::ActionCount, &(count + 1));

        // ✅ Authority comes from the authenticated signer, not an argument.
        env.events().publish(
            (symbol_short!("execute"),),
            (actor, amount, count + 1),
        );
    }

    pub fn action_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ActionCount)
            .unwrap_or(0)
    }
}
