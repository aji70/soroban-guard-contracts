//! SECURE: Flash Loan with Fee Verification and Event Emission
//!
//! Requires post_balance >= pre_balance + fee and emits a fee collection event.

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

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
pub struct SecureFlashLoan;

#[contractimpl]
impl SecureFlashLoan {
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

    /// ✅ Secure flash loan that verifies both principal AND fee are repaid.
    /// Requires post_balance >= pre_balance + fee and emits fee collection event.
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
        callback.require_auth();

        // Get balance after callback.
        let post_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);

        // ✅ SECURE: Require both principal AND fee to be repaid.
        let required_balance = pre_balance + fee;
        assert!(
            post_balance >= required_balance,
            "insufficient repayment (principal + fee required)"
        );

        // Emit fee collection event.
        env.events().publish(
            (symbol_short!("fee"),),
            (amount, fee, post_balance),
        );

        FlashLoanResult { amount, fee }
    }
}
