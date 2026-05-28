//! VULNERABLE: Interest Is Not Accrued Before Borrow Limit Checks
//!
//! `borrow` reads the borrower's stored debt without first accruing interest,
//! so the solvency check runs against stale principal-only debt.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

/// Interest charged per ledger elapsed (basis points of outstanding debt).
const INTEREST_BPS_PER_LEDGER: i128 = 100; // 1% per ledger
pub const BORROW_LIMIT: i128 = 1_000;

#[contracttype]
pub enum DataKey {
    Debt(Address),
    LastAccrualLedger(Address),
    LastMarketLedger,
}

fn get_debt(env: &Env, borrower: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Debt(borrower.clone()))
        .unwrap_or(0)
}

fn set_debt(env: &Env, borrower: &Address, debt: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Debt(borrower.clone()), &debt);
}

fn get_last_accrual(env: &Env, borrower: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::LastAccrualLedger(borrower.clone()))
        .unwrap_or(0)
}

fn set_last_accrual(env: &Env, borrower: &Address, ledger: u32) {
    env.storage().persistent().set(
        &DataKey::LastAccrualLedger(borrower.clone()),
        &ledger,
    );
}

/// Accrue simple interest on `borrower` debt up to the current ledger.
pub fn accrue_borrower(env: &Env, borrower: &Address) {
    let debt = get_debt(env, borrower);
    if debt == 0 {
        set_last_accrual(env, borrower, env.ledger().sequence());
        return;
    }
    let last = get_last_accrual(env, borrower);
    let now = env.ledger().sequence();
    if now <= last {
        return;
    }
    let elapsed = (now - last) as i128;
    let interest = debt * INTEREST_BPS_PER_LEDGER * elapsed / 10_000;
    set_debt(env, borrower, debt + interest);
    set_last_accrual(env, borrower, now);
}

pub fn accrue_market(env: &Env) {
    env.storage()
        .persistent()
        .set(&DataKey::LastMarketLedger, &env.ledger().sequence());
}

#[contract]
pub struct BorrowWithoutAccrual;

#[contractimpl]
impl BorrowWithoutAccrual {
    pub fn initialize(env: Env, borrower: Address, initial_borrow: i128) {
        borrower.require_auth();
        assert!(initial_borrow > 0 && initial_borrow <= BORROW_LIMIT, "invalid borrow");
        set_debt(&env, &borrower, initial_borrow);
        set_last_accrual(&env, &borrower, env.ledger().sequence());
        accrue_market(&env);
    }

    /// VULNERABLE: limit check uses stale stored debt — interest is not accrued first.
    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        assert!(amount > 0, "amount must be positive");

        // ❌ Missing: accrue_market(&env); accrue_borrower(&env, &borrower);
        let debt = get_debt(&env, &borrower);
        assert!(debt + amount <= BORROW_LIMIT, "borrow limit exceeded");
        set_debt(&env, &borrower, debt + amount);
    }

    pub fn debt(env: Env, borrower: Address) -> i128 {
        get_debt(&env, &borrower)
    }

    /// View debt as it would be after accruing interest (for tests).
    pub fn debt_after_accrual(env: Env, borrower: Address) -> i128 {
        projected_debt(&env, &borrower)
    }
}

pub fn projected_debt(env: &Env, borrower: &Address) -> i128 {
    let debt = get_debt(env, borrower);
    if debt == 0 {
        return 0;
    }
    let last = get_last_accrual(env, borrower);
    let now = env.ledger().sequence();
    if now <= last {
        return debt;
    }
    let elapsed = (now - last) as i128;
    debt + debt * INTEREST_BPS_PER_LEDGER * elapsed / 10_000
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureBorrowWithoutAccrualClient;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, Env};

    const INITIAL_BORROW: i128 = 900;

    fn setup_vulnerable(env: &Env) -> (Address, BorrowWithoutAccrualClient<'_>) {
        let id = env.register_contract(None, BorrowWithoutAccrual);
        let client = BorrowWithoutAccrualClient::new(env, &id);
        let borrower = Address::generate(env);
        client.initialize(&borrower, &INITIAL_BORROW);
        (borrower, client)
    }

    fn setup_secure(env: &Env) -> (Address, SecureBorrowWithoutAccrualClient<'_>) {
        let id = env.register_contract(None, secure::SecureBorrowWithoutAccrual);
        let client = SecureBorrowWithoutAccrualClient::new(env, &id);
        let borrower = Address::generate(env);
        client.initialize(&borrower, &INITIAL_BORROW);
        (borrower, client)
    }

    fn advance_ledgers(env: &Env, n: u32) {
        env.ledger().with_mut(|l| l.sequence_number += n);
    }

    /// After interest accrues past the limit, vulnerable path still allows another borrow.
    #[test]
    fn test_vulnerable_allows_borrow_after_interest_past_limit() {
        let env = Env::default();
        env.mock_all_auths();

        let (borrower, client) = setup_vulnerable(&env);
        advance_ledgers(&env, 12);

        assert!(
            client.debt_after_accrual(&borrower) > BORROW_LIMIT,
            "interest should push debt over limit"
        );
        assert!(client.debt(&borrower) < BORROW_LIMIT, "stored debt is stale");

        client.borrow(&borrower, &50);
        assert_eq!(client.debt(&borrower), INITIAL_BORROW + 50);
    }

    /// Boundary: advance exactly until accrued debt reaches the limit, then borrow.
    #[test]
    fn test_vulnerable_boundary_exact_ledger_over_limit() {
        let env = Env::default();
        env.mock_all_auths();

        let (borrower, client) = setup_vulnerable(&env);
        // 900 + 900*1%*11 = 999 at 11 ledgers; 12th ledger pushes to 1008 (> limit).
        advance_ledgers(&env, 12);
        assert_eq!(client.debt_after_accrual(&borrower), 1008);

        client.borrow(&borrower, &1);
        assert_eq!(client.debt(&borrower), INITIAL_BORROW + 1);
    }

    /// Secure path accrues first and rejects the additional borrow.
    #[test]
    #[should_panic(expected = "borrow limit exceeded")]
    fn test_secure_rejects_borrow_after_accrual() {
        let env = Env::default();
        env.mock_all_auths();

        let (borrower, client) = setup_secure(&env);
        advance_ledgers(&env, 12);

        assert!(client.debt_after_accrual(&borrower) > BORROW_LIMIT);
        client.borrow(&borrower, &1);
    }
}
