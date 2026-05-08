#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const MIN_COLLATERAL_RATIO: i128 = 150; // 150%
const LIQUIDATION_THRESHOLD: i128 = 120; // 120%

#[contracttype]
pub enum DataKey {
    Collateral(Address),
    Debt(Address),
}

#[contract]
pub struct SecureLending;

#[contractimpl]
impl SecureLending {
    pub fn initialize(env: Env, borrower: Address) {
        borrower.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(borrower.clone()), &0i128);
        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower), &0i128);
    }

    pub fn deposit_collateral(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        let key = DataKey::Collateral(borrower);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current
            .checked_add(amount)
            .expect("collateral overflow");
        env.storage().persistent().set(&key, &updated);
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        let collateral = Self::get_collateral(&env, &borrower);
        let debt = Self::get_debt(&env, &borrower);
        let new_debt = debt.checked_add(amount).expect("debt overflow");

        // Enforce collateral_value >= borrow_amount * MIN_COLLATERAL_RATIO / 100
        let lhs = collateral.checked_mul(100).expect("collateral overflow");
        let rhs = new_debt
            .checked_mul(MIN_COLLATERAL_RATIO)
            .expect("debt ratio overflow");
        if lhs < rhs {
            panic!("insufficient collateral");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower), &new_debt);
    }

    pub fn repay(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        let debt = Self::get_debt(&env, &borrower);
        if amount > debt {
            panic!("repay amount exceeds debt");
        }

        let new_debt = debt - amount;
        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower), &new_debt);
    }

    pub fn liquidate(env: Env, borrower: Address, caller: Address) {
        // Any caller can liquidate, but must authorize their own action.
        caller.require_auth();

        let collateral = Self::get_collateral(&env, &borrower);
        let debt = Self::get_debt(&env, &borrower);

        if debt == 0 {
            panic!("nothing to liquidate");
        }

        let lhs = collateral.checked_mul(100).expect("collateral overflow");
        let rhs = debt
            .checked_mul(LIQUIDATION_THRESHOLD)
            .expect("debt threshold overflow");
        if lhs >= rhs {
            panic!("position not liquidatable");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Collateral(borrower.clone()), &0i128);
        env.storage().persistent().set(&DataKey::Debt(borrower), &0i128);
    }

    pub fn get_position(env: Env, borrower: Address) -> (i128, i128) {
        (
            Self::get_collateral(&env, &borrower),
            Self::get_debt(&env, &borrower),
        )
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
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, SecureLendingClient<'static>) {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureLending);
        let client = SecureLendingClient::new(&env, &contract_id);
        (env, client)
    }

    #[test]
    #[should_panic(expected = "insufficient collateral")]
    fn test_borrow_without_sufficient_collateral_panics() {
        let (env, client) = setup();
        let borrower = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&borrower);
        client.deposit_collateral(&borrower, &100);
        client.borrow(&borrower, &70); // Needs 105 collateral at 150% ratio.
    }

    #[test]
    fn test_position_below_liquidation_threshold_can_be_liquidated_by_any_caller() {
        let (env, client) = setup();
        let borrower = Address::generate(&env);
        let liquidator = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&borrower);
        client.deposit_collateral(&borrower, &150);
        client.borrow(&borrower, &100);

        // Simulate collateral value drop (e.g. oracle repricing) by lowering stored collateral.
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(borrower.clone()), &110i128);

        client.liquidate(&borrower, &liquidator);
        assert_eq!(client.get_position(&borrower), (0, 0));
    }

    #[test]
    fn test_repay_restores_borrower_collateral_access() {
        let (env, client) = setup();
        let borrower = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&borrower);
        client.deposit_collateral(&borrower, &150);
        client.borrow(&borrower, &100);
        assert_eq!(client.get_position(&borrower), (150, 100));

        client.repay(&borrower, &100);
        assert_eq!(client.get_position(&borrower), (150, 0));

        // After full repayment, borrower can safely borrow again against the same collateral.
        client.borrow(&borrower, &100);
        assert_eq!(client.get_position(&borrower), (150, 100));
    }
}
