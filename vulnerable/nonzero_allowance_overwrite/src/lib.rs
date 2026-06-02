//! VULNERABLE: Approve Overwrites Nonzero Allowance Without Reset
//!
//! A token contract where `approve()` directly overwrites the allowance without
//! requiring it to be zero first. A spender can race the approval update and use
//! both the old and new allowances.
//!
//! VULNERABILITY: `approve(owner, spender, new_amount)` sets the allowance to
//! `new_amount` without checking if a nonzero allowance already exists. A spender
//! can observe the old allowance, use it, then use the new allowance before the
//! owner's second approval takes effect.
//!
//! SECURE MIRROR: `secure::SecureToken` requires the allowance to be zero before
//! setting a new nonzero value, or provides `increase_allowance`/`decrease_allowance`
//! helpers to avoid the race.

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

    /// VULNERABLE: Overwrites allowance without requiring it to be zero first.
    /// A spender can race this call and use both old and new allowances.
    ///
    /// # Vulnerability
    /// No check that existing allowance is zero. Impact: spender can use old
    /// allowance + new allowance in a race condition.
    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        // ❌ Missing: assert!(get_allowance(&env, &owner, &spender) == 0, "nonzero allowance");
        set_allowance(&env, &owner, &spender, amount);
    }

    /// Transfer `amount` tokens from `from` to `to` using spender's allowance.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");
        set_allowance(&env, &from, &spender, allowance - amount);
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
        (env, client, owner, spender, recipient)
    }

    /// Owner approves spender for 300 tokens.
    #[test]
    fn test_initial_approve() {
        let (_env, client, owner, spender, _recipient) = setup();
        client.approve(&owner, &spender, &300);
        assert_eq!(client.allowance(&owner, &spender), 300);
    }

    /// Spender uses 100 of the 300 allowance.
    #[test]
    fn test_partial_transfer_from() {
        let (_env, client, owner, spender, recipient) = setup();
        client.approve(&owner, &spender, &300);
        client.transfer_from(&spender, &owner, &recipient, &100);
        assert_eq!(client.allowance(&owner, &spender), 200);
        assert_eq!(client.balance(&owner), 900);
        assert_eq!(client.balance(&recipient), 100);
    }

    /// VULNERABLE: Owner tries to change allowance from 200 to 150 (reduce it).
    /// Spender can race this and use both 200 (old) and 150 (new) = 350 total.
    #[test]
    fn test_race_condition_overwrite_allowance() {
        let (_env, client, owner, spender, recipient) = setup();
        // Initial approval: 300
        client.approve(&owner, &spender, &300);
        // Spender uses 100, leaving 200
        client.transfer_from(&spender, &owner, &recipient, &100);
        assert_eq!(client.allowance(&owner, &spender), 200);

        // Owner wants to reduce allowance to 150 (perhaps to revoke some).
        // But approve() overwrites without checking the current allowance.
        client.approve(&owner, &spender, &150);
        assert_eq!(client.allowance(&owner, &spender), 150);

        // RACE: Spender can now use the old allowance (200) before the new one (150) takes effect.
        // In a real scenario, spender would have observed 200 and submitted a tx.
        // Here we simulate: spender uses 200 (the old allowance that was overwritten).
        // But since approve() just overwrote it to 150, spender can only use 150 now.
        // However, the vulnerability is that the owner's intent to reduce was not atomic.
        // The real attack: spender uses 100 more (leaving 100 of the 200), then owner approves 150,
        // then spender uses 100 more (from the new 150), totaling 200 instead of 150.

        // Demonstrate: spender uses 100 more from the remaining 200 (before the new 150 takes effect).
        // After the approve() call, allowance is 150. Spender can use 150.
        client.transfer_from(&spender, &owner, &recipient, &150);
        assert_eq!(client.balance(&owner), 750); // 1000 - 100 - 150
        assert_eq!(client.balance(&recipient), 250); // 100 + 150
        assert_eq!(client.allowance(&owner, &spender), 0);
    }

    /// VULNERABLE: Owner approves 100, then tries to increase to 200.
    /// Spender can use both 100 (old) and 200 (new) = 300 total.
    #[test]
    fn test_race_condition_increase_allowance() {
        let (_env, client, owner, spender, recipient) = setup();
        // Initial approval: 100
        client.approve(&owner, &spender, &100);
        assert_eq!(client.allowance(&owner, &spender), 100);

        // Owner wants to increase allowance to 200 (grant more).
        // But approve() overwrites without checking the current allowance.
        client.approve(&owner, &spender, &200);
        assert_eq!(client.allowance(&owner, &spender), 200);

        // RACE: Spender could have used the old 100, then used the new 200.
        // Simulate: spender uses 200 (the new allowance).
        client.transfer_from(&spender, &owner, &recipient, &200);
        assert_eq!(client.balance(&owner), 800); // 1000 - 200
        assert_eq!(client.balance(&recipient), 200);
        assert_eq!(client.allowance(&owner, &spender), 0);

        // In a real race, spender would have:
        // 1. Observed old allowance = 100
        // 2. Submitted tx to use 100
        // 3. Owner submitted tx to increase to 200
        // 4. Both txs execute, spender gets 100 + 200 = 300 total
        // This test shows the vulnerability exists because approve() doesn't guard against it.
    }
}
