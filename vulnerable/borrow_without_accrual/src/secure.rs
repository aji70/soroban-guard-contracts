//! SECURE: accrue market and borrower interest before any borrow decision.

use super::{accrue_borrower, accrue_market, set_debt, BORROW_LIMIT, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

fn get_debt(env: &Env, borrower: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Debt(borrower.clone()))
        .unwrap_or(0)
}

#[contract]
pub struct SecureBorrowWithoutAccrual;

#[contractimpl]
impl SecureBorrowWithoutAccrual {
    pub fn initialize(env: Env, borrower: Address, initial_borrow: i128) {
        borrower.require_auth();
        assert!(initial_borrow > 0 && initial_borrow <= BORROW_LIMIT, "invalid borrow");
        set_debt(&env, &borrower, initial_borrow);
        env.storage().persistent().set(
            &DataKey::LastAccrualLedger(borrower.clone()),
            &env.ledger().sequence(),
        );
        accrue_market(&env);
    }

    /// SECURE: accrue interest before evaluating the borrow limit.
    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        assert!(amount > 0, "amount must be positive");

        accrue_market(&env);
        accrue_borrower(&env, &borrower);

        let debt = get_debt(&env, &borrower);
        assert!(debt + amount <= BORROW_LIMIT, "borrow limit exceeded");
        set_debt(&env, &borrower, debt + amount);
    }

    pub fn debt(env: Env, borrower: Address) -> i128 {
        get_debt(&env, &borrower)
    }

    pub fn debt_after_accrual(env: Env, borrower: Address) -> i128 {
        super::projected_debt(&env, &borrower)
    }
}
