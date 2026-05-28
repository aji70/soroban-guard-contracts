//! VULNERABLE: Interest Index Can Be Reset by New Deposits
//!
//! When total deposits transition from zero to nonzero, the deposit path
//! reinitializes the global borrow index, erasing accrued interest pricing.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const INDEX_SCALE: i128 = 1_000_000;
const INDEX_GROWTH_BPS_PER_LEDGER: i128 = 100; // 1% index growth per ledger

#[contracttype]
pub enum DataKey {
    TotalSupply,
    BorrowIndex,
    LastIndexLedger,
    Debt(Address),
    TotalDebt,
}

fn get_supply(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::TotalSupply)
        .unwrap_or(0)
}

fn set_supply(env: &Env, supply: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::TotalSupply, &supply);
}

fn get_borrow_index(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::BorrowIndex)
        .unwrap_or(INDEX_SCALE)
}

fn set_borrow_index(env: &Env, index: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::BorrowIndex, &index);
}

fn get_last_index_ledger(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::LastIndexLedger)
        .unwrap_or(0)
}

fn set_last_index_ledger(env: &Env, ledger: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::LastIndexLedger, &ledger);
}

fn get_principal(env: &Env, borrower: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Debt(borrower.clone()))
        .unwrap_or(0)
}

fn set_principal(env: &Env, borrower: &Address, principal: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Debt(borrower.clone()), &principal);
}

fn get_total_debt(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::TotalDebt)
        .unwrap_or(0)
}

fn set_total_debt(env: &Env, debt: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::TotalDebt, &debt);
}

pub fn accrue_index(env: &Env) {
    let index = get_borrow_index(env);
    let last = get_last_index_ledger(env);
    let now = env.ledger().sequence();
    if now <= last {
        return;
    }
    let elapsed = (now - last) as i128;
    let growth = index * INDEX_GROWTH_BPS_PER_LEDGER * elapsed / 10_000;
    set_borrow_index(env, index + growth);
    set_last_index_ledger(env, now);
}

pub fn debt_value(env: &Env, borrower: &Address) -> i128 {
    let principal = get_principal(env, borrower);
    if principal == 0 {
        return 0;
    }
    principal * get_borrow_index(env) / INDEX_SCALE
}

#[contract]
pub struct InterestIndexReset;

#[contractimpl]
impl InterestIndexReset {
    pub fn initialize(env: Env, supplier: Address, deposit_amount: i128) {
        supplier.require_auth();
        assert!(deposit_amount > 0, "deposit must be positive");
        set_supply(&env, deposit_amount);
        set_borrow_index(&env, INDEX_SCALE);
        set_last_index_ledger(&env, env.ledger().sequence());
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        accrue_index(&env);
        assert!(amount > 0, "borrow must be positive");
        assert!(get_supply(&env) >= amount, "insufficient liquidity");

        let principal = get_principal(&env, &borrower);
        set_principal(&env, &borrower, principal + amount);
        set_total_debt(&env, get_total_debt(&env) + amount);
        set_supply(&env, get_supply(&env) - amount);
    }

    /// VULNERABLE: reinitializes the borrow index when supply returns from zero.
    pub fn deposit(env: Env, supplier: Address, amount: i128) {
        supplier.require_auth();
        assert!(amount > 0, "deposit must be positive");

        let supply = get_supply(&env);
        if supply == 0 {
            // ❌ Resets accrued index pricing when liquidity returns.
            set_borrow_index(&env, INDEX_SCALE);
            set_last_index_ledger(&env, env.ledger().sequence());
        }
        set_supply(&env, supply + amount);
    }

    pub fn withdraw(env: Env, supplier: Address, amount: i128) {
        supplier.require_auth();
        let supply = get_supply(&env);
        assert!(amount <= supply, "insufficient supply");
        set_supply(&env, supply - amount);
    }

    pub fn borrow_index(env: Env) -> i128 {
        accrue_index(&env);
        get_borrow_index(&env)
    }

    pub fn debt(env: Env, borrower: Address) -> i128 {
        accrue_index(&env);
        debt_value(&env, &borrower)
    }

    pub fn total_supply(env: Env) -> i128 {
        get_supply(&env)
    }

    pub fn total_debt_outstanding(env: Env) -> i128 {
        get_total_debt(&env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureInterestIndexResetClient;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, Env};

    const INITIAL_SUPPLY: i128 = 1_000;
    const BORROW_AMOUNT: i128 = 500;
    const DRAIN_AMOUNT: i128 = 500;

    fn setup_vulnerable(env: &Env) -> (Address, Address, InterestIndexResetClient<'_>) {
        let id = env.register_contract(None, InterestIndexReset);
        let client = InterestIndexResetClient::new(env, &id);
        let supplier = Address::generate(env);
        let borrower = Address::generate(env);
        client.initialize(&supplier, &INITIAL_SUPPLY);
        client.borrow(&borrower, &BORROW_AMOUNT);
        (borrower, supplier, client)
    }

    fn setup_secure(env: &Env) -> (Address, Address, SecureInterestIndexResetClient<'_>) {
        let id = env.register_contract(None, secure::SecureInterestIndexReset);
        let client = SecureInterestIndexResetClient::new(env, &id);
        let supplier = Address::generate(env);
        let borrower = Address::generate(env);
        client.initialize(&supplier, &INITIAL_SUPPLY);
        client.borrow(&borrower, &BORROW_AMOUNT);
        (borrower, supplier, client)
    }

    fn advance_ledgers(env: &Env, n: u32) {
        env.ledger().with_mut(|l| l.sequence_number += n);
    }

    /// Drain supply to zero and redeposit — vulnerable path resets index and misprices debt.
    #[test]
    fn test_vulnerable_resets_index_after_zero_supply_deposit() {
        let env = Env::default();
        env.mock_all_auths();

        let (borrower, supplier, client) = setup_vulnerable(&env);
        advance_ledgers(&env, 10);

        let debt_before = client.debt(&borrower);
        let index_before = client.borrow_index();
        assert!(debt_before > BORROW_AMOUNT, "interest should accrue");
        assert!(index_before > INDEX_SCALE, "index should grow");

        client.withdraw(&supplier, &DRAIN_AMOUNT);
        assert_eq!(client.total_supply(), 0);

        client.deposit(&supplier, &100);

        let debt_after = client.debt(&borrower);
        assert_eq!(client.borrow_index(), INDEX_SCALE, "index was reset");
        assert!(
            debt_after < debt_before,
            "debt mispriced downward after index reset"
        );
    }

    /// Boundary: drain to exactly zero then deposit one unit triggers the reset.
    #[test]
    fn test_vulnerable_boundary_one_unit_deposit_resets_index() {
        let env = Env::default();
        env.mock_all_auths();

        let (borrower, supplier, client) = setup_vulnerable(&env);
        advance_ledgers(&env, 5);

        client.withdraw(&supplier, &DRAIN_AMOUNT);
        assert_eq!(client.total_supply(), 0);

        client.deposit(&supplier, &1);
        assert_eq!(client.borrow_index(), INDEX_SCALE);
        assert_eq!(client.debt(&borrower), BORROW_AMOUNT);
    }

    /// Secure path preserves the borrow index across the zero-supply transition.
    #[test]
    fn test_secure_preserves_index_across_zero_supply() {
        let env = Env::default();
        env.mock_all_auths();

        let (borrower, supplier, client) = setup_secure(&env);
        advance_ledgers(&env, 10);

        let debt_before = client.debt(&borrower);
        let index_before = client.borrow_index();

        client.withdraw(&supplier, &DRAIN_AMOUNT);
        client.deposit(&supplier, &1);

        assert_eq!(client.borrow_index(), index_before);
        assert_eq!(client.debt(&borrower), debt_before);
    }
}
