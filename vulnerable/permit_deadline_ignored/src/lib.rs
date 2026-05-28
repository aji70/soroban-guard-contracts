//! VULNERABLE: Permit Deadline Ignored
//!
//! A token contract where `permit` accepts a signed off-chain approval that
//! includes a `deadline` field, but the contract never compares it against the
//! current ledger timestamp. Expired signatures remain valid indefinitely.
//!
//! VULNERABILITY: `permit()` stores the allowance without checking
//! `deadline >= env.ledger().timestamp()`, so any expired permit can still be
//! replayed to set an allowance.
//!
//! SECURE MIRROR: `secure::SecureToken` rejects the call when
//! `env.ledger().timestamp() > deadline`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address), // (owner, spender)
    Nonce(Address),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

pub fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

pub fn get_allowance(env: &Env, owner: &Address, spender: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(owner.clone(), spender.clone()))
        .unwrap_or(0)
}

pub fn set_allowance(env: &Env, owner: &Address, spender: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Allowance(owner.clone(), spender.clone()), &amount);
}

pub fn get_nonce(env: &Env, owner: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Nonce(owner.clone()))
        .unwrap_or(0)
}

pub fn bump_nonce(env: &Env, owner: &Address) {
    let n = get_nonce(env, owner);
    env.storage()
        .persistent()
        .set(&DataKey::Nonce(owner.clone()), &(n + 1));
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

    /// ❌ VULNERABLE: `deadline` is accepted but never checked against the
    /// current ledger timestamp. An expired permit sets the allowance just as
    /// well as a fresh one.
    pub fn permit(
        env: Env,
        owner: Address,
        spender: Address,
        amount: i128,
        deadline: u64,
        // In a real contract the signature would be verified here; omitted to
        // keep the fixture focused on the deadline-check vulnerability.
        _nonce: u64,
    ) {
        owner.require_auth();

        // ❌ Missing: assert!(env.ledger().timestamp() <= deadline, "permit expired");

        let _ = deadline; // deadline is silently ignored

        bump_nonce(&env, &owner);
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");
        set_allowance(&env, &from, &spender, allowance - amount);
        let from_bal = get_balance(&env, &from);
        assert!(from_bal >= amount, "insufficient balance");
        set_balance(&env, &from, from_bal - amount);
        let to_bal = get_balance(&env, &to);
        set_balance(&env, &to, to_bal + amount);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }

    pub fn nonce(env: Env, owner: Address) -> u64 {
        get_nonce(&env, &owner)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup() -> (Env, VulnerableTokenClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &id);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        client.mint(&owner, &1000);
        (env, client, owner, spender)
    }

    /// A valid (non-expired) permit sets the allowance.
    #[test]
    fn test_valid_permit_sets_allowance() {
        let (env, client, owner, spender) = setup();
        env.ledger().set_timestamp(1000);
        let deadline = 2000u64; // in the future
        client.permit(&owner, &spender, &500, &deadline, &0);
        assert_eq!(client.allowance(&owner, &spender), 500);
    }

    /// DEMONSTRATES VULNERABILITY: an expired permit still sets the allowance.
    /// The deadline (500) is in the past relative to the current timestamp (1000),
    /// but the contract accepts it without complaint.
    #[test]
    fn test_expired_permit_still_sets_allowance() {
        let (env, client, owner, spender) = setup();
        env.ledger().set_timestamp(1000);
        let expired_deadline = 500u64; // already past
        // ❌ Should panic with "permit expired" but succeeds instead.
        client.permit(&owner, &spender, &500, &expired_deadline, &0);
        assert_eq!(client.allowance(&owner, &spender), 500);
    }

    /// Boundary: deadline exactly equal to current timestamp should be the
    /// last valid moment. Vulnerable contract accepts it (correct), but also
    /// accepts anything earlier (incorrect).
    #[test]
    fn test_boundary_deadline_equals_timestamp() {
        let (env, client, owner, spender) = setup();
        env.ledger().set_timestamp(1000);
        // deadline == timestamp: should be accepted (boundary).
        client.permit(&owner, &spender, &100, &1000u64, &0);
        assert_eq!(client.allowance(&owner, &spender), 100);
    }

    /// Nonce is incremented after each permit call.
    #[test]
    fn test_nonce_increments() {
        let (env, client, owner, spender) = setup();
        env.ledger().set_timestamp(1000);
        assert_eq!(client.nonce(&owner), 0);
        client.permit(&owner, &spender, &100, &2000u64, &0);
        assert_eq!(client.nonce(&owner), 1);
    }
}
