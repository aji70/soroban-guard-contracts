//! VULNERABLE: Allowance Not Decremented After transfer_from
//!
//! A token contract where `transfer_from` checks the spender's allowance but
//! never reduces it after use. This lets a spender drain the full owner balance
//! with repeated calls using a single approval.
//!
//! VULNERABILITY: `transfer_from()` asserts `allowance >= amount` but never
//! calls `set_allowance` to decrement it — the allowance is reusable forever.
//!
//! SECURE MIRROR: `secure::SecureToken` decrements the allowance by `amount`
//! after every successful `transfer_from`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address), // (owner, spender)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
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

fn do_transfer(env: &Env, from: &Address, to: &Address, amount: i128) {
    let from_bal = get_balance(env, from);
    assert!(from_bal >= amount, "insufficient balance");
    set_balance(env, from, from_bal - amount);
    let to_bal = get_balance(env, to);
    set_balance(env, to, to_bal + amount);
}

// ── Vulnerable token ──────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    /// Mint `amount` tokens to `to`. No auth check — for test setup.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current + amount);
    }

    /// Approve `spender` to transfer up to `amount` tokens from `owner`. Requires owner auth.
    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &spender, amount);
    }

    /// VULNERABLE: checks the allowance but never decrements it after use.
    /// A spender can reuse the same approval indefinitely to drain the owner.
    ///
    /// # Vulnerability
    /// Missing `set_allowance` decrement. Impact: single approval enables unlimited transfers.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");
        // ❌ Missing: set_allowance(&env, &from, &spender, allowance - amount);
        do_transfer(&env, &from, &to, amount);
    }

    /// Returns the balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    /// Returns the current allowance granted by `owner` to `spender`, defaulting to 0.
    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        VulnerableTokenClient<'static>,
        Address,
        Address,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &id);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.mint(&owner, &1000);
        client.approve(&owner, &spender, &300);
        (env, client, owner, spender, recipient)
    }

    /// First transfer_from succeeds normally.
    #[test]
    fn test_first_transfer_from_succeeds() {
        let (_env, client, owner, spender, recipient) = setup();
        client.transfer_from(&spender, &owner, &recipient, &300);
        assert_eq!(client.balance(&owner), 700);
        assert_eq!(client.balance(&recipient), 300);
    }

    /// Second transfer_from with the same allowance also succeeds.
    /// Demonstrates the vulnerability — allowance was never decremented.
    #[test]
    fn test_second_transfer_from_reuses_allowance() {
        let (_env, client, owner, spender, recipient) = setup();
        client.transfer_from(&spender, &owner, &recipient, &300);
        // Allowance should be 0 now in a correct implementation, but it's still 300.
        assert_eq!(client.allowance(&owner, &spender), 300);
        // Second call drains another 300 — this is the bug.
        client.transfer_from(&spender, &owner, &recipient, &300);
        assert_eq!(client.balance(&owner), 400);
        assert_eq!(client.balance(&recipient), 600);
    }
}
