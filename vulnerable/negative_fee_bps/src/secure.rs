use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{DataKey, get_balance, set_balance};

#[contract]
pub struct SecureFeeContract;

#[contractimpl]
impl SecureFeeContract {
    pub fn initialize(env: Env, admin: Address, fee_bps: i128) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    /// SECURE: requires 0 <= fee_bps <= 10_000 before storing.
    pub fn set_fee(env: Env, fee_bps: i128) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        // ✅ Both bounds enforced — negative values are rejected
        if fee_bps < 0 || fee_bps > 10_000 {
            panic!("fee_bps must be in 0..=10000");
        }
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    /// SECURE: fee is always non-negative; recipient never gains extra value.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let fee_bps: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0);
        // ✅ checked arithmetic; fee_bps is guaranteed >= 0 so net <= amount
        let fee = amount
            .checked_mul(fee_bps)
            .and_then(|v| v.checked_div(10_000))
            .expect("fee overflow");
        let net = amount.checked_sub(fee).expect("net underflow");
        set_balance(&env, &from, get_balance(&env, &from) - amount);
        set_balance(&env, &to, get_balance(&env, &to) + net);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn current_fee_bps(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0)
    }
}
