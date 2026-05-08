use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{DataKey, MAX_FEE_BPS};

#[contract]
pub struct SecureFeeContract;

#[contractimpl]
impl SecureFeeContract {
    pub fn initialize(env: Env, admin: Address, fee_bps: i128) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    /// SECURE: rejects fee_bps above 10_000 (100%) before writing to storage.
    pub fn set_fee(env: Env, fee_bps: i128) {
        Self::require_admin(&env);
        // ✅ Cap: fee cannot exceed 100%
        if fee_bps > MAX_FEE_BPS {
            panic!("fee_bps exceeds 10000");
        }
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    /// SECURE: checked arithmetic prevents i128 overflow.
    pub fn calculate_fee(env: Env, amount: i128) -> i128 {
        let fee_bps: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0);
        // ✅ checked_mul + checked_div — panics on overflow instead of wrapping
        amount
            .checked_mul(fee_bps)
            .and_then(|res| res.checked_div(10_000))
            .expect("fee calculation overflow")
    }

    pub fn current_fee_bps(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap();
        admin.require_auth();
    }
}
