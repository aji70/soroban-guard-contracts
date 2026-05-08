//! VULNERABLE: Flash Loan with No Repayment Check
//!
//! A flash loan contract that transfers funds to a borrower and invokes their
//! callback, but never asserts that the borrowed amount was returned within
//! the same transaction. This allows a borrower to permanently drain the
//! lending pool without repaying.
//!
//! VULNERABILITY: `flash_loan()` calls the borrower's `on_flash_loan` callback
//! but performs no balance check afterward — funds can be extracted for free.
//!
//! SECURE MIRROR: `secure::SecureFlashLoan` snapshots the pool balance before
//! the callback and panics if it has not been fully restored after.
//!
//! # Repayment model
//!
//! Soroban forbids re-entrant calls, so a borrower cannot call back into the
//! lending contract while `flash_loan` is on the call stack. Repayment is
//! therefore modelled via a separate `RepaymentLedger` contract (not in the
//! call stack) that the borrower writes to during the callback. The lending
//! contract reads the ledger *after* the callback returns to determine whether
//! the loan was repaid.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    PoolBalance,
    /// Address of the RepaymentLedger contract used in tests.
    LedgerContract,
}

// ── RepaymentLedger: a neutral third-party contract ──────────────────────────
//
// Neither the lender nor the borrower — so it is never on the call stack when
// either of them calls it, avoiding the re-entry restriction.

#[contracttype]
pub enum LedgerKey {
    Repaid,
}

#[contract]
pub struct RepaymentLedger;

#[contractimpl]
impl RepaymentLedger {
    /// Borrower calls this to record that it has repaid `amount`.
    pub fn record_repayment(env: Env, amount: i128) {
        let current: i128 = env
            .storage()
            .temporary()
            .get(&LedgerKey::Repaid)
            .unwrap_or(0);
        env.storage()
            .temporary()
            .set(&LedgerKey::Repaid, &(current + amount));
    }

    /// Lender calls this to read (and clear) the recorded repayment.
    pub fn consume_repayment(env: Env) -> i128 {
        let amount: i128 = env
            .storage()
            .temporary()
            .get(&LedgerKey::Repaid)
            .unwrap_or(0);
        env.storage().temporary().remove(&LedgerKey::Repaid);
        amount
    }
}

// ── Borrower callback interface ───────────────────────────────────────────────

pub mod callback {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "BorrowerClient")]
    pub trait Borrower {
        fn on_flash_loan(env: Env, loan_contract: Address, amount: i128);
    }
}

// ── Vulnerable lending contract ───────────────────────────────────────────────

#[contract]
pub struct FlashLoanNoCheck;

#[contractimpl]
impl FlashLoanNoCheck {
    /// Seed the lending pool with `amount` tokens from `from`. Requires from auth.
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
    /// ❌ Calls the borrower callback but NEVER checks that the pool balance
    ///    was restored — the borrower can keep the funds.
    pub fn flash_loan(env: Env, borrower: Address, amount: i128) {
        let pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        assert!(pool >= amount, "insufficient pool liquidity");

        // Deduct from pool before callback (simulates transfer out).
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(pool - amount));

        // Invoke borrower — they are supposed to repay, but we never verify.
        callback::BorrowerClient::new(&env, &borrower)
            .on_flash_loan(&env.current_contract_address(), &amount);

        // ❌ Missing: assert pool balance >= pool_before
    }

    /// Returns the current pool balance, defaulting to 0.
    pub fn pool_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0)
    }
}

// ── Honest borrower ───────────────────────────────────────────────────────────
//
// Records repayment in the RepaymentLedger (a neutral contract not in the
// call stack), then the lender reads it after the callback returns.

pub mod honest {
    use super::{DataKey, RepaymentLedgerClient};
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct HonestBorrower;

    #[contractimpl]
    impl HonestBorrower {
        pub fn on_flash_loan(env: Env, _loan_contract: Address, amount: i128) {
            let ledger_id: Address = env
                .storage()
                .persistent()
                .get(&DataKey::LedgerContract)
                .expect("ledger contract not configured");
            RepaymentLedgerClient::new(&env, &ledger_id).record_repayment(&amount);
        }
    }
}

// ── Dishonest borrower ────────────────────────────────────────────────────────

pub mod dishonest {
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct DishonestBorrower;

    #[contractimpl]
    impl DishonestBorrower {
        pub fn on_flash_loan(_env: Env, _loan_contract: Address, _amount: i128) {
            // ❌ Does nothing — keeps the borrowed funds.
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (Address, FlashLoanNoCheckClient<'_>) {
        let id = env.register_contract(None, FlashLoanNoCheck);
        let client = FlashLoanNoCheckClient::new(env, &id);
        let seeder = Address::generate(env);
        client.deposit(&seeder, &1000);
        (id, client)
    }

    /// Honest borrower records repayment — pool balance is fully restored.
    /// The vulnerable contract succeeds (no check), but the pool is intact
    /// because the honest borrower did the right thing.
    #[test]
    fn test_honest_borrower_repays() {
        let env = Env::default();
        env.mock_all_auths();

        let ledger_id = env.register_contract(None, RepaymentLedger);
        let borrower_id = env.register_contract(None, honest::HonestBorrower);

        // Tell the honest borrower which ledger to use.
        env.as_contract(&borrower_id, || {
            env.storage()
                .persistent()
                .set(&DataKey::LedgerContract, &ledger_id);
        });

        let (_loan_id, client) = setup(&env);
        client.flash_loan(&borrower_id, &500);

        // Simulate the lender consuming the repayment from the ledger.
        let ledger_client = RepaymentLedgerClient::new(&env, &ledger_id);
        let repaid = ledger_client.consume_repayment();
        assert_eq!(repaid, 500);
        // Pool was drained (vulnerable contract never restored it from ledger).
        assert_eq!(client.pool_balance(), 500);
    }

    /// Dishonest borrower keeps the funds — vulnerable contract still succeeds.
    /// This demonstrates the vulnerability: the pool is permanently drained.
    #[test]
    fn test_dishonest_borrower_drains_pool() {
        let env = Env::default();
        env.mock_all_auths();

        let (_loan_id, client) = setup(&env);
        let borrower_id = env.register_contract(None, dishonest::DishonestBorrower);

        // Should NOT succeed in a secure contract, but here it does.
        client.flash_loan(&borrower_id, &500);

        // Pool has been permanently drained — this is the bug.
        assert_eq!(client.pool_balance(), 500);
    }
}
