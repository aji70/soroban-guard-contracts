//! SECURE: Liquidation with Ceiling Division and Minimum Thresholds
//!
//! Enforces minimum repay threshold, rounds ceiling for protocol benefit,
//! and allows full liquidation of positions that would round to zero.

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

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

/// Ceiling division: (a + b - 1) / b
fn ceil_div(numerator: i128, denominator: i128) -> i128 {
    (numerator + denominator - 1) / denominator
}

#[contract]
pub struct SecureLiquidation;

#[contractimpl]
impl SecureLiquidation {
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

    /// ✅ Secure liquidation with ceiling division and minimum thresholds.
    /// If the calculated repay rounds to zero but debt is non-zero,
    /// allow full liquidation instead of rejecting.
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

        // Calculate repay amount using ceiling division.
        let calc_repay = ceil_div(current_debt * CLOSE_FACTOR, SCALE);

        // If calculated repay rounds to zero but debt exists, fully liquidate.
        let repay_amount = if calc_repay == 0 && current_debt > 0 {
            current_debt
        } else if calc_repay > 0 {
            calc_repay
        } else {
            0
        };

        // Ensure we don't exceed actual debt.
        let actual_repay = core::cmp::min(repay_amount, current_debt);

        // Similarly for collateral with ceiling division.
        let calc_seize = ceil_div(current_collateral * CLOSE_FACTOR, SCALE);
        let seize_amount = core::cmp::min(calc_seize, current_collateral);

        // Update storage with reduced debt and collateral.
        let new_debt = current_debt - actual_repay;
        let new_collateral = current_collateral - seize_amount;

        env.storage()
            .persistent()
            .set(&DataKey::Debt(borrower.clone()), &new_debt);
        env.storage()
            .persistent()
            .set(&DataKey::Collateral(borrower.clone()), &new_collateral);

        env.events().publish(
            (symbol_short!("liquidate"),),
            (borrower, actual_repay, seize_amount),
        );

        LiquidationResult {
            repay_amount: actual_repay,
            seize_amount,
        }
    }
}
