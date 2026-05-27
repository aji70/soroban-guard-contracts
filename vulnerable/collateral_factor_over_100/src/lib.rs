//! VULNERABLE: market configuration allows collateral factors above 100%.
//!
//! A lending market where the admin can set `collateral_factor` to any
//! positive percentage. Because `borrow()` uses `collateral * factor / 100`
//! without capping `factor` at 100, a borrower can take on more debt than
//! the value of their collateral and make the market insolvent immediately.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    CollateralFactor,
    Collateral(Address),
    Debt(Address),
}

#[contract]
pub struct CollateralFactorOver100;

#[contractimpl]
impl CollateralFactorOver100 {
    /// Initialize the market with an admin and a starting collateral factor.
    ///
    /// VULNERABILITY: `collateral_factor` may exceed 100%.
    pub fn initialize_vulnerable(env: Env, admin: Address, collateral_factor: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::CollateralFactor, &collateral_factor);
    }

    /// Update the market collateral factor.
    ///
    /// VULNERABILITY: no guard against values above 100.
    pub fn set_collateral_factor_vulnerable(env: Env, admin: Address, collateral_factor: i128) {
        admin.require_auth();
        let stored_admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        if stored_admin != admin {
            panic!("only admin can update collateral factor");
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

        // The market allows factor > 100, so `new_debt` may exceed collateral.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::SecureLendingClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, CollateralFactorOver100Client<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let id = env.register_contract(None, CollateralFactorOver100);
        let client = CollateralFactorOver100Client::new(&env, &id);
        (env, client, admin, borrower)
    }

    #[test]
    fn test_vulnerable_allows_collateral_factor_above_100() {
        let (env, client, admin, borrower) = setup();
        client.initialize_vulnerable(&admin, &120);
        client.deposit_collateral(&borrower, &100);

        // With a 120% collateral factor, borrower can borrow more value than collateral.
        client.borrow(&borrower, &120);
        assert_eq!(client.get_position(&borrower), (100, 120));
    }

    #[test]
    #[should_panic(expected = "collateral_factor cannot exceed 100")]
    fn test_secure_rejects_collateral_factor_above_100() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);

        client.initialize(&admin, &120);
    }

    #[test]
    fn test_secure_allows_up_to_100_percent() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);

        client.initialize(&admin, &100);
        client.deposit_collateral(&borrower, &100);
        client.borrow(&borrower, &100);
        assert_eq!(client.get_position(&borrower), (100, 100));
    }
}
