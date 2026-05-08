//! SECURE: Flash Loan with Repayment Check
//!
//! After invoking the borrower callback, reads the repayment amount from the
//! RepaymentLedger and panics if the full loan was not recorded as repaid.
//! The pool balance is also restored from the ledger.

use super::{callback, DataKey, RepaymentLedgerClient};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureFlashLoan;

#[contractimpl]
impl SecureFlashLoan {
    /// Seed the lending pool.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(current + amount));
    }

    /// Issue a flash loan of `amount` to `borrower`.
    ///
    /// ✅ After the callback, reads the RepaymentLedger and panics if the
    ///    borrower did not record full repayment — protecting the pool.
    pub fn flash_loan(env: Env, borrower: Address, amount: i128, ledger: Address) {
        let balance_before: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);

        assert!(balance_before >= amount, "insufficient pool liquidity");

        // Deduct from pool before callback.
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(balance_before - amount));

        // Invoke borrower callback.
        callback::BorrowerClient::new(&env, &borrower)
            .on_flash_loan(&env.current_contract_address(), &amount);

        // ✅ SECURE: Read repayment from the neutral ledger contract.
        let repaid = RepaymentLedgerClient::new(&env, &ledger).consume_repayment();
        assert!(repaid >= amount, "flash loan not repaid");

        // Restore the pool with the repaid amount.
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(current + repaid));
    }

    pub fn pool_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dishonest, honest, DataKey, RepaymentLedger};
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (Address, SecureFlashLoanClient<'_>) {
        let id = env.register_contract(None, SecureFlashLoan);
        let client = SecureFlashLoanClient::new(env, &id);
        let seeder = Address::generate(env);
        client.deposit(&seeder, &1000);
        (id, client)
    }

    /// Honest borrower repays — secure contract succeeds and pool is restored.
    #[test]
    fn test_secure_honest_borrower_repays() {
        let env = Env::default();
        env.mock_all_auths();

        let ledger_id = env.register_contract(None, RepaymentLedger);
        let borrower_id = env.register_contract(None, honest::HonestBorrower);

        env.as_contract(&borrower_id, || {
            env.storage()
                .persistent()
                .set(&DataKey::LedgerContract, &ledger_id);
        });

        let (_loan_id, client) = setup(&env);
        client.flash_loan(&borrower_id, &500, &ledger_id);

        assert_eq!(client.pool_balance(), 1000);
    }

    /// Dishonest borrower — secure contract panics, pool is protected.
    #[test]
    #[should_panic(expected = "flash loan not repaid")]
    fn test_secure_dishonest_borrower_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let ledger_id = env.register_contract(None, RepaymentLedger);
        let (_loan_id, client) = setup(&env);
        let borrower_id = env.register_contract(None, dishonest::DishonestBorrower);

        client.flash_loan(&borrower_id, &500, &ledger_id);
    }
}
