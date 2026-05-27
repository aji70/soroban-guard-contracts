//! SECURE: borrow index is never reset while debt remains outstanding.

use super::{
    accrue_index, debt_value, get_borrow_index, get_principal, get_supply, get_total_debt,
    set_borrow_index, set_last_index_ledger, set_principal, set_supply, set_total_debt, INDEX_SCALE,
};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureInterestIndexReset;

#[contractimpl]
impl SecureInterestIndexReset {
    pub fn initialize(env: Env, supplier: Address, deposit_amount: i128) {
        supplier.require_auth();
        assert!(deposit_amount > 0, "deposit must be positive");
        set_supply(&env, deposit_amount);
        set_borrow_index(&env, INDEX_SCALE);
        set_last_index_ledger(&env, env.ledger().sequence());
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        accrue_index(&env);
        assert!(amount > 0, "borrow must be positive");
        assert!(get_supply(&env) >= amount, "insufficient liquidity");

        let principal = get_principal(&env, &borrower);
        set_principal(&env, &borrower, principal + amount);
        set_total_debt(&env, get_total_debt(&env) + amount);
        set_supply(&env, get_supply(&env) - amount);
    }

    /// SECURE: deposits only update supply; index is independent of supply state.
    pub fn deposit(env: Env, supplier: Address, amount: i128) {
        supplier.require_auth();
        assert!(amount > 0, "deposit must be positive");

        let supply = get_supply(&env);
        if supply == 0 && get_total_debt(&env) > 0 {
            // ✅ Preserve index while debt exists — never reinitialize.
            accrue_index(&env);
        }
        set_supply(&env, supply + amount);
    }

    pub fn withdraw(env: Env, supplier: Address, amount: i128) {
        supplier.require_auth();
        let supply = get_supply(&env);
        assert!(amount <= supply, "insufficient supply");
        set_supply(&env, supply - amount);
    }

    pub fn borrow_index(env: Env) -> i128 {
        accrue_index(&env);
        get_borrow_index(&env)
    }

    pub fn debt(env: Env, borrower: Address) -> i128 {
        accrue_index(&env);
        debt_value(&env, &borrower)
    }

    pub fn total_supply(env: Env) -> i128 {
        get_supply(&env)
    }

    pub fn total_debt_outstanding(env: Env) -> i128 {
        get_total_debt(&env)
    }
}
