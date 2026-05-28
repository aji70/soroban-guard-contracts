use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureLending;

#[contractimpl]
impl SecureLending {
    pub fn initialize(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::TransferFails, &false);
    }

    pub fn set_transfer_fails(env: Env, fails: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::TransferFails, &fails);
    }

    fn do_token_transfer(env: &Env) -> Result<(), ()> {
        let fails: bool = env
            .storage()
            .persistent()
            .get(&DataKey::TransferFails)
            .unwrap_or(false);
        if fails {
            Err(())
        } else {
            Ok(())
        }
    }

    /// SECURE: propagates the transfer error — state is only written after
    /// a confirmed successful external call.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();

        // ✅ Propagate the error; panic on failure so no state is written.
        Self::do_token_transfer(&env).expect("token transfer failed");

        let key = DataKey::CreditBalance(user.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    pub fn credit_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CreditBalance(user))
            .unwrap_or(0)
    }
}
