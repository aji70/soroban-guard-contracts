//! SECURE mirror: validate signed input before casting to unsigned.
//!
//! The positivity check is performed on the original `i128` value.  Only after
//! the check passes is a safe `u128::try_from` conversion attempted, which
//! panics on any remaining negative value rather than silently wrapping.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// ✅ Validates `amount > 0` on the signed type before converting.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        // ✅ Guard on the signed value — negative inputs are caught here.
        assert!(amount > 0, "amount must be positive");
        // ✅ Checked conversion: panics if somehow still negative (belt-and-suspenders).
        let unsigned = u128::try_from(amount).expect("amount out of range");
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &unsigned);
    }

    pub fn get_balance(env: Env, user: Address) -> u128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}
