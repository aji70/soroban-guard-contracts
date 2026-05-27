#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    CollateralFactor,
    Collateral(Address),
    Debt(Address),
}

#[contract]
pub struct SecureLending;

#[contractimpl]
impl SecureLending {
    pub fn initialize(env: Env, admin: Address, collateral_factor: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        if collateral_factor <= 0 || collateral_factor > 100 {
            panic!("collateral_factor cannot exceed 100");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::CollateralFactor, &collateral_factor);
    }

    pub fn set_collateral_factor(env: Env, admin: Address, collateral_factor: i128) {
        admin.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        if stored_admin != admin {
            panic!("only admin can update collateral factor");
        }
        if collateral_factor <= 0 || collateral_factor > 100 {
            panic!("collateral_factor cannot exceed 100");
        }
        env.storage()
            .persistent()
            .set(&DataKey::CollateralFactor, &collateral_factor);
    }

    pub fn deposit_collateral(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Collateral(borrower.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        let collateral = Self::get_collateral(&env, &borrower);
        let collateral_factor = Self::get_collateral_factor(&env);
        let debt = Self::get_debt(&env, &borrower);
        let new_debt = debt.checked_add(amount).expect("debt overflow");

        let lhs = collateral
            .checked_mul(collateral_factor)
            .expect("collateral overflow");
        let rhs = new_debt.checked_mul(100).expect("debt overflow");
        if lhs < rhs {
            panic!("insufficient collateral");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower), &new_debt);
    }

    pub fn get_position(env: Env, borrower: Address) -> (i128, i128) {
        (
            Self::get_collateral(&env, &borrower),
            Self::get_debt(&env, &borrower),
        )
    }

    pub fn get_collateral_factor(env: Env) -> i128 {
        Self::get_collateral_factor(&env)
    }

    fn get_collateral_factor(env: &Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CollateralFactor)
            .unwrap_or(0)
    }

    fn get_collateral(env: &Env, borrower: &Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Collateral(borrower.clone()))
            .unwrap_or(0)
    }

    fn get_debt(env: &Env, borrower: &Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Debt(borrower.clone()))
            .unwrap_or(0)
    }
}
