//! VULNERABLE: Delegate Signer Mismatch Allows Unauthorized Delegated Transfer
//!
//! A token-like contract that accepts a `delegate` address parameter for
//! delegated transfers but calls `owner.require_auth()` instead of
//! `delegate.require_auth()`. This allows a malicious caller to consume
//! another delegate's allowance because the signer and allowance spender
//! are not bound together.
//!
//! VULNERABILITY: `transfer_from()` accepts `delegate` as a parameter but
//! authorizes `owner` — any delegate with any allowance from that owner can
//! spend any other delegate's allowance.
//!
//! SECURE MIRROR: `secure::SecureToken` calls `delegate.require_auth()` and
//! keys allowances by `(owner, delegate)` to bind the signer to the allowance.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
    /// Allowance keyed by (owner, delegate).
    Allowance(Address, Address),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

pub(crate) fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

pub(crate) fn get_allowance(env: &Env, owner: &Address, delegate: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(owner.clone(), delegate.clone()))
        .unwrap_or(0)
}

pub(crate) fn set_allowance(env: &Env, owner: &Address, delegate: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Allowance(owner.clone(), delegate.clone()), &amount);
}

// ── Vulnerable token ──────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current + amount);
    }

    pub fn approve(env: Env, owner: Address, delegate: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &delegate, amount);
    }

    /// Delegated transfer — delegate spends owner's allowance.
    ///
    /// ❌ BUG: Authorizes `owner` instead of `delegate` — any delegate with
    ///    any allowance from that owner can consume any other delegate's allowance.
    pub fn transfer_from(
        env: Env,
        delegate: Address,
        owner: Address,
        to: Address,
        amount: i128,
    ) -> i128 {
        // ❌ Wrong signer — should be delegate.require_auth()
        owner.require_auth();

        let allowance = get_allowance(&env, &owner, &delegate);
        assert!(allowance >= amount, "insufficient allowance");

        let owner_bal = get_balance(&env, &owner);
        assert!(owner_bal >= amount, "insufficient balance");

        set_balance(&env, &owner, owner_bal - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
        set_allowance(&env, &owner, &delegate, allowance - amount);

        allowance - amount
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, delegate: Address) -> i128 {
        get_allowance(&env, &owner, &delegate)
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
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &id);
        let owner = Address::generate(&env);
        let legitimate_delegate = Address::generate(&env);
        let attacker_delegate = Address::generate(&env);
        let recipient = Address::generate(&env);

        client.mint(&owner, &1000);
        // Owner approves legitimate_delegate for 300.
        client.approve(&owner, &legitimate_delegate, &300);
        // Owner also approves attacker_delegate for 50 (unrelated allowance).
        client.approve(&owner, &attacker_delegate, &50);

        (
            env,
            client,
            owner,
            legitimate_delegate,
            attacker_delegate,
            recipient,
        )
    }

    /// Attacker delegate can consume legitimate delegate's allowance because
    /// the contract authorizes owner instead of delegate — demonstrates the bug.
    #[test]
    fn test_attacker_delegate_can_spend_other_allowance() {
        let (_env, client, owner, legitimate_delegate, attacker_delegate, recipient) = setup();

        // Attacker calls transfer_from with legitimate_delegate's allowance.
        // ❌ Vulnerable contract authorizes owner, so this succeeds.
        client.transfer_from(&legitimate_delegate, &owner, &recipient, &200);

        // Legitimate delegate's allowance was consumed by the attacker.
        assert_eq!(client.allowance(&owner, &legitimate_delegate), 100);
        assert_eq!(client.balance(&recipient), 200);

        // Attacker's own allowance is untouched.
        assert_eq!(client.allowance(&owner, &attacker_delegate), 50);
    }

    /// Legitimate delegate can use their own allowance (expected behavior).
    #[test]
    fn test_legitimate_delegate_can_spend() {
        let (_env, client, owner, legitimate_delegate, _attacker_delegate, recipient) = setup();

        client.transfer_from(&legitimate_delegate, &owner, &recipient, &100);

        assert_eq!(client.allowance(&owner, &legitimate_delegate), 200);
        assert_eq!(client.balance(&recipient), 100);
    }
}
