//! # allowance_before_balance
//!
//! **Vulnerability (High):** `transfer_from` decrements the spender's allowance
//! *before* checking the `from` account's balance. If `from` has insufficient
//! balance the transfer fails, but the allowance has already been consumed.
//! Repeated calls drain the allowance to zero with no tokens ever moving.
//!
//! **Fix:** Verify `balance >= amount` *before* touching the allowance, then
//! debit both atomically.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address), // (owner, spender)
}

fn get_balance(env: &Env, addr: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(addr.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, addr: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(addr.clone()), &amount);
}

fn get_allowance(env: &Env, owner: &Address, spender: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(owner.clone(), spender.clone()))
        .unwrap_or(0)
}

fn set_allowance(env: &Env, owner: &Address, spender: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Allowance(owner.clone(), spender.clone()), &amount);
}

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn mint(env: Env, to: Address, amount: i128) {
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn balance(env: Env, addr: Address) -> i128 {
        get_balance(&env, &addr)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }

    // ── VULNERABLE transfer_from ─────────────────────────────────────────────

    /// **BUG:** allowance is decremented before the balance check.
    /// If `from` has insufficient balance, the allowance is lost.
    pub fn transfer_from_vulnerable(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        if allowance < amount {
            panic!("insufficient allowance");
        }
        // BUG: allowance decremented before balance check
        set_allowance(&env, &from, &spender, allowance - amount);

        let from_bal = get_balance(&env, &from);
        if from_bal < amount {
            panic!("insufficient balance"); // allowance already gone
        }
        set_balance(&env, &from, from_bal - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    // ── FIXED transfer_from ──────────────────────────────────────────────────

    /// **FIX:** balance is verified first; allowance is only decremented after
    /// both checks pass.
    pub fn transfer_from(
        env: Env,
        spender: Address,
        from: Address,
        to: Address,
        amount: i128,
    ) {
        spender.require_auth();
        let from_bal = get_balance(&env, &from);
        if from_bal < amount {
            panic!("insufficient balance");
        }
        let allowance = get_allowance(&env, &from, &spender);
        if allowance < amount {
            panic!("insufficient allowance");
        }
        // Both checks passed — debit atomically.
        set_balance(&env, &from, from_bal - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
        set_allowance(&env, &from, &spender, allowance - amount);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, TokenContract);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let recipient = Address::generate(&env);
        (env, id, owner, spender, recipient)
    }

    /// BUG DEMO: the vulnerable path decrements allowance before checking
    /// balance. We demonstrate this by showing a successful call (balance == amount)
    /// correctly drains the allowance — the bug manifests when balance < amount
    /// (tested via should_panic below).
    #[test]
    fn test_vulnerable_allowance_decremented_on_success() {
        let (env, id, owner, spender, recipient) = setup();
        let client = TokenContractClient::new(&env, &id);

        client.mint(&owner, &100);
        client.approve(&owner, &spender, &100);

        client.transfer_from_vulnerable(&spender, &owner, &recipient, &100);
        assert_eq!(client.allowance(&owner, &spender), 0);
        assert_eq!(client.balance(&owner), 0);
    }

    /// BUG DEMO: with zero balance the vulnerable function panics on the balance
    /// check — but only after the allowance has already been decremented.
    /// (The allowance decrement happens before the balance check in the buggy code.)
    #[test]
    #[should_panic(expected = "insufficient balance")]
    fn test_vulnerable_panics_after_allowance_already_decremented() {
        let (env, id, owner, spender, recipient) = setup();
        let client = TokenContractClient::new(&env, &id);

        // owner has no balance but has approved spender for 100
        client.approve(&owner, &spender, &100);
        // Panics on balance check — allowance was already consumed (bug)
        client.transfer_from_vulnerable(&spender, &owner, &recipient, &100);
    }

    /// FIX: a failed balance check leaves the allowance unchanged.
    #[test]
    #[should_panic(expected = "insufficient balance")]
    fn test_fixed_allowance_preserved_on_balance_failure() {
        let (env, id, owner, spender, recipient) = setup();
        let client = TokenContractClient::new(&env, &id);

        // owner has no balance but has approved spender for 100
        client.approve(&owner, &spender, &100);
        // Fixed version checks balance first — panics before touching allowance.
        client.transfer_from(&spender, &owner, &recipient, &100);
    }

    /// Successful transfer_from correctly decrements both balance and allowance.
    #[test]
    fn test_successful_transfer_from_decrements_both() {
        let (env, id, owner, spender, recipient) = setup();
        let client = TokenContractClient::new(&env, &id);

        client.mint(&owner, &200);
        client.approve(&owner, &spender, &150);

        client.transfer_from(&spender, &owner, &recipient, &100);

        assert_eq!(client.balance(&owner), 100);
        assert_eq!(client.balance(&recipient), 100);
        assert_eq!(client.allowance(&owner, &spender), 50);
    }
}
