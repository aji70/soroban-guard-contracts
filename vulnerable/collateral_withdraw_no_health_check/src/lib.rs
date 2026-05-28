//! VULNERABLE: Collateral Withdrawal Skips Post-Withdraw Health Check
//!
//! Withdrawals only check that the account has enough collateral balance. They
//! do not verify that the remaining collateral still backs the debt.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

const BPS: i128 = 10_000;
const LIQUIDATION_THRESHOLD_BPS: i128 = 7_500;

#[contracttype]
pub enum DataKey {
    Collateral(Address),
    Debt(Address),
}

fn collateral(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Collateral(user.clone()))
        .unwrap_or(0)
}

fn debt(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Debt(user.clone()))
        .unwrap_or(0)
}

fn set_collateral(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Collateral(user.clone()), &amount);
}

fn set_debt(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Debt(user.clone()), &amount);
}

fn borrow_limit(collateral: i128) -> i128 {
    collateral * LIQUIDATION_THRESHOLD_BPS / BPS
}

fn assert_healthy(collateral: i128, debt: i128) {
    assert!(borrow_limit(collateral) >= debt, "unhealthy position");
}

#[contract]
pub struct CollateralWithdrawNoHealthCheck;

#[contractimpl]
impl CollateralWithdrawNoHealthCheck {
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
        // VULNERABLE: writes reduced collateral without checking health factor.
        set_collateral(&env, &user, current - amount);
    }

    pub fn position(env: Env, user: Address) -> (i128, i128, i128) {
        let col = collateral(&env, &user);
        let owed = debt(&env, &user);
        (col, owed, borrow_limit(col))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::{SecureCollateralWithdraw, SecureCollateralWithdrawClient};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn vulnerable_withdraw_makes_position_insolvent() {
        let env = Env::default();
        env.mock_all_auths();
        let user = Address::generate(&env);
        let id = env.register_contract(None, CollateralWithdrawNoHealthCheck);
        let client = CollateralWithdrawNoHealthCheckClient::new(&env, &id);

        client.deposit(&user, &100);
        client.borrow(&user, &74);
        client.withdraw(&user, &20);

        assert_eq!(client.position(&user), (80, 74, 60));
    }

    #[test]
    #[should_panic(expected = "unhealthy position")]
    fn secure_rejects_withdrawal_that_breaks_health() {
        let env = Env::default();
        env.mock_all_auths();
        let user = Address::generate(&env);
        let id = env.register_contract(None, SecureCollateralWithdraw);
        let client = SecureCollateralWithdrawClient::new(&env, &id);

        client.deposit(&user, &100);
        client.borrow(&user, &74);
        client.withdraw(&user, &20);
    }
}
