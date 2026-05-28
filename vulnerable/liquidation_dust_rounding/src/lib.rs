//! VULNERABLE: Liquidation Rounding Lets Bad Debt Survive as Dust
//!
//! A lending protocol where liquidation applies close factor and seize amount
//! using integer division that floors to zero for dust-sized positions.
//! Attackers can split loans into dust to avoid cleanup.
//!
//! VULNERABILITY: Integer division with floor (/) applied to close_factor
//! and seize calculations rounds small amounts to zero, leaving bad debt.
//!
//! SECURE MIRROR: `secure::SecureLiquidation` enforces minimum repay threshold,
//! rounds in favor of protocol (ceiling), and allows full liquidation of
//! positions that round to zero.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

const CLOSE_FACTOR: i128 = 50; // 50% = 50 / 100
const SCALE: i128 = 100;

#[contracttype]
pub enum DataKey {
    Debt(Address),
    Collateral(Address),
}

#[contracttype]
#[derive(Clone)]
pub struct LiquidationResult {
    pub repay_amount: i128,
    pub seize_amount: i128,
}

#[contract]
pub struct VulnerableLiquidation;

#[contractimpl]
impl VulnerableLiquidation {
    /// Initialize a borrow position with debt and collateral.
    pub fn borrow(env: Env, borrower: Address, debt: i128, collateral: i128) {
        borrower.require_auth();
        env.storage().persistent().set(&DataKey::Debt(borrower.clone()), &debt);
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(borrower.clone()), &collateral);
        env.events()
            .publish((symbol_short!("borrow"),), (borrower, debt, collateral));
    }

    /// Get current debt for a borrower.
    pub fn get_debt(env: Env, borrower: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Debt(borrower))
            .unwrap_or(0)
    }

    /// Get current collateral for a borrower.
    pub fn get_collateral(env: Env, borrower: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Collateral(borrower))
            .unwrap_or(0)
    }

    /// VULNERABLE: Liquidate a position using floor division.
    /// For small debts, (debt * CLOSE_FACTOR) / SCALE can round to zero,
    /// leaving the debt intact and allowing dust bad debt to survive.
    pub fn liquidate(env: Env, borrower: Address) -> LiquidationResult {
        let current_debt: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Debt(borrower.clone()))
            .unwrap_or(0);
        let current_collateral: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Collateral(borrower.clone()))
            .unwrap_or(0);

        // ❌ Floor division: small debts round to zero.
        let repay_amount = (current_debt * CLOSE_FACTOR) / SCALE;
        let seize_amount = (current_collateral * CLOSE_FACTOR) / SCALE;

        // Update storage with reduced debt and collateral.
        let new_debt = current_debt - repay_amount;
        let new_collateral = current_collateral - seize_amount;

        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower.clone()), &new_debt);
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(borrower.clone()), &new_collateral);

        env.events().publish(
            (symbol_short!("liquidate"),),
            (borrower, repay_amount, seize_amount),
        );

        LiquidationResult {
            repay_amount,
            seize_amount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_dust_position_liquidation_returns_zero() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableLiquidation);
        let client = VulnerableLiquidationClient::new(&env, &id);
        let borrower = Address::generate(&env);

        // Create a dust-sized unhealthy position: 1 unit debt, 2 units collateral.
        client.borrow(&borrower, &1, &2);
        assert_eq!(client.get_debt(&borrower), 1);
        assert_eq!(client.get_collateral(&borrower), 2);

        // Attempt liquidation.
        let result = client.liquidate(&borrower);

        // ❌ Vulnerable path: (1 * 50) / 100 = 0 (floors to zero).
        assert_eq!(result.repay_amount, 0);
        assert_eq!(result.seize_amount, 1);

        // Debt is not reduced; bad debt survives as dust.
        assert_eq!(client.get_debt(&borrower), 1);
        assert_eq!(client.get_collateral(&borrower), 1);
    }

    #[test]
    fn test_boundary_close_factor_rounds_to_zero() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableLiquidation);
        let client = VulnerableLiquidationClient::new(&env, &id);
        let borrower = Address::generate(&env);

        // Debt of 99: (99 * 50) / 100 = 49.5 → 49.
        // Debt of 1: (1 * 50) / 100 = 0.5 → 0 (boundary case).
        client.borrow(&borrower, &1, &2);

        let result = client.liquidate(&borrower);

        // ❌ Vulnerable path accepts the call but clears nothing.
        assert_eq!(result.repay_amount, 0);

        // Debt remains unchanged.
        assert_eq!(client.get_debt(&borrower), 1);
    }

    #[test]
    fn test_secure_path_clears_dust_fully() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureLiquidation);
        let client = secure::SecureLiquidationClient::new(&env, &id);
        let borrower = Address::generate(&env);

        // Create a dust position.
        client.borrow(&borrower, &1, &2);

        // Secure path fully clears dust.
        let result = client.liquidate(&borrower);

        // Secure path should fully liquidate dust positions.
        assert!(result.repay_amount >= 1);

        // Debt should be fully cleared.
        assert_eq!(client.get_debt(&borrower), 0);
    }
}
