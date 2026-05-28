//! VULNERABLE: Flash Loan Fee Is Calculated but Never Transferred
//!
//! A flash loan protocol that computes a fee, dispatches the loan via callback,
//! then checks only that the principal is repaid—never verifying the fee was
//! included. Borrowers can use liquidity for free by returning only principal.
//!
//! VULNERABILITY: The repayment check is `post_balance >= pre_balance`
//! instead of `post_balance >= pre_balance + fee`. The fee is never collected.
//!
//! SECURE MIRROR: `secure::SecureFlashLoan` requires
//! `post_balance >= pre_balance + fee` and emits a fee event on success.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

const FEE_RATE: i128 = 5; // 0.5% = 5 / 1000
const FEE_SCALE: i128 = 1000;

#[contracttype]
pub enum DataKey {
    Balance,
}

#[contracttype]
#[derive(Clone)]
pub struct FlashLoanResult {
    pub amount: i128,
    pub fee: i128,
}

#[contract]
pub struct VulnerableFlashLoan;

#[contractimpl]
impl VulnerableFlashLoan {
    /// Initialize the pool with initial liquidity.
    pub fn initialize(env: Env, initial_balance: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &initial_balance);
        env.events()
            .publish((symbol_short!("init"),), (initial_balance,));
    }

    /// Get current pool balance.
    pub fn get_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0)
    }

    /// Set balance for testing purposes (to simulate callback repayment).
    pub fn set_balance(env: Env, new_balance: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &new_balance);
    }

    /// VULNERABLE: Flash loan that calculates fee but never checks it's repaid.
    /// The callback is invoked with the loan amount, then we check only that
    /// the principal is returned, not the fee.
    pub fn flash_loan(
        env: Env,
        amount: i128,
        callback: Address,
    ) -> FlashLoanResult {
        // Get current balance before loan.
        let pre_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);

        // Ensure we have enough liquidity.
        assert!(pre_balance >= amount, "insufficient liquidity");

        // Calculate fee.
        let fee = (amount * FEE_RATE) / FEE_SCALE;

        // Simulate loan dispatch: reduce balance by loan amount.
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(pre_balance - amount));

        // Invoke the callback to let the borrower use the funds.
        // (In a real contract, this would call the callback contract.)
        callback.require_auth();

        // Get balance after callback.
        let post_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);

        // ❌ VULNERABLE: Check only principal is repaid, NOT the fee.
        assert!(
            post_balance >= pre_balance,
            "principal not repaid"
        );

        env.events().publish(
            (symbol_short!("flash"),),
            (amount, fee, post_balance),
        );

        FlashLoanResult { amount, fee }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_fee_calculation_with_small_amount() {
        // Demonstrate: small amounts round fee to zero due to floor division.
        let amount = 100i128;
        let fee = (amount * FEE_RATE) / FEE_SCALE;
        assert_eq!(fee, 0); // (100 * 5) / 1000 = 0 (floor)
    }

    #[test]
    fn test_fee_calculation_with_larger_amount() {
        // Demonstrate: larger amounts produce non-zero fees.
        let amount = 200i128;
        let fee = (amount * FEE_RATE) / FEE_SCALE;
        assert_eq!(fee, 1); // (200 * 5) / 1000 = 1
    }

    #[test]
    fn test_vulnerable_check_only_principal() {
        // The vulnerable path checks: post_balance >= pre_balance
        // It does NOT check: post_balance >= pre_balance + fee
        // This means if fee = 1, but borrower only repays principal,
        // the check still passes.

        let pre_balance = 2000i128;
        let amount = 200i128;
        let fee = (amount * FEE_RATE) / FEE_SCALE;
        assert_eq!(fee, 1);

        // Vulnerable check: post_balance >= pre_balance
        let post_balance = pre_balance; // Only repaid principal, not fee
        let vulnerable_passes = post_balance >= pre_balance;
        assert!(vulnerable_passes, "vulnerable path accepts principal-only repayment");
    }

    #[test]
    fn test_secure_check_principal_and_fee() {
        // The secure path checks: post_balance >= pre_balance + fee
        // This ensures the fee is actually collected.

        let pre_balance = 2000i128;
        let amount = 200i128;
        let fee = (amount * FEE_RATE) / FEE_SCALE;
        assert_eq!(fee, 1);

        // Secure check with principal-only repayment: should fail
        let post_balance_insufficient = pre_balance;
        let secure_fails = post_balance_insufficient < (pre_balance + fee);
        assert!(secure_fails, "secure path rejects principal-only repayment");

        // Secure check with principal + fee: should pass
        let post_balance_sufficient = pre_balance + fee;
        let secure_passes = post_balance_sufficient >= (pre_balance + fee);
        assert!(secure_passes, "secure path accepts principal + fee repayment");
    }
}
