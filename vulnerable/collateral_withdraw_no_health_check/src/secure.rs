//! SECURE: Withdrawal simulates the resulting position before writing state.

use super::{assert_healthy, collateral, debt, set_collateral, set_debt};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureCollateralWithdraw;

#[contractimpl]
impl SecureCollateralWithdraw {
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        set_collateral(&env, &user, collateral(&env, &user) + amount);
    }

    pub fn borrow(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let new_debt = debt(&env, &user) + amount;
        assert_healthy(collateral(&env, &user), new_debt);
        set_debt(&env, &user, new_debt);
    }

    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let current = collateral(&env, &user);
        assert!(current >= amount, "insufficient collateral");
        let remaining = current - amount;
        assert_healthy(remaining, debt(&env, &user));
        set_collateral(&env, &user, remaining);
    }

    pub fn position(env: Env, user: Address) -> (i128, i128, i128) {
        let col = collateral(&env, &user);
        let owed = debt(&env, &user);
        (col, owed, super::borrow_limit(col))
    }
}
