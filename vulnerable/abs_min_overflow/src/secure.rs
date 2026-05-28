//! SECURE mirror: reject i128::MIN before calling abs(), or use checked_abs().
//!
//! `i128::checked_abs()` returns `None` for `i128::MIN`; we treat that as an
//! explicit error rather than letting it panic or silently wrap.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureRisk;

#[contractimpl]
impl SecureRisk {
    /// ✅ Uses `checked_abs()` and panics with a clear message on i128::MIN.
    pub fn record_delta(env: Env, user: Address, delta: i128) {
        user.require_auth();
        // ✅ checked_abs returns None for i128::MIN — explicit rejection.
        let abs_delta = delta.checked_abs().expect("delta out of range");
        env.storage()
            .persistent()
            .set(&DataKey::DebtDelta(user), &abs_delta);
    }

    pub fn get_delta(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::DebtDelta(user))
            .unwrap_or(0)
    }
}
