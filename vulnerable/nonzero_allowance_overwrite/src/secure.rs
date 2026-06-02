//! SECURE: Approve Requires Zero Allowance or Uses Increase/Decrease Helpers
//!
//! Identical API to VulnerableToken but `approve()` requires the current
//! allowance to be zero before setting a new nonzero value. This prevents
//! the race condition where a spender can use both old and new allowances.

use super::{do_transfer, get_allowance, get_balance, set_allowance, set_balance};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current + amount);
    }

    /// ✅ Requires allowance to be zero before setting a new nonzero value.
    /// This prevents the race condition where spender uses both old and new allowances.
    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        if amount != 0 {
            let current = get_allowance(&env, &owner, &spender);
            assert!(
                current == 0,
                "nonzero allowance: must reset to zero before setting new value"
            );
        }
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");
        set_allowance(&env, &from, &spender, allowance - amount);
        do_transfer(&env, &from, &to, amount);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, SecureTokenClient<'static>, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &id);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.mint(&owner, &1000);
        (env, client, owner, spender, recipient)
    }

    /// Initial approval succeeds.
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

    /// ✅ Attempting to overwrite nonzero allowance panics.
    #[test]
    #[should_panic(expected = "nonzero allowance")]
    fn test_overwrite_nonzero_allowance_rejected() {
        let (_env, client, owner, spender, _recipient) = setup();
        client.approve(&owner, &spender, &300);
        // Attempt to change to 150 — must panic because allowance is nonzero.
        client.approve(&owner, &spender, &150);
    }

    /// ✅ Must reset to zero before setting a new value.
    #[test]
    fn test_reset_then_approve_succeeds() {
        let (_env, client, owner, spender, recipient) = setup();
        client.approve(&owner, &spender, &300);
        client.transfer_from(&spender, &owner, &recipient, &300);
        // Allowance is now 0.
        assert_eq!(client.allowance(&owner, &spender), 0);
        // Now we can set a new allowance.
        client.approve(&owner, &spender, &200);
        assert_eq!(client.allowance(&owner, &spender), 200);
    }

    /// ✅ Can set allowance to zero at any time (revoke).
    #[test]
    fn test_revoke_allowance() {
        let (_env, client, owner, spender, _recipient) = setup();
        client.approve(&owner, &spender, &300);
        // Revoke by setting to zero — always allowed.
        client.approve(&owner, &spender, &0);
        assert_eq!(client.allowance(&owner, &spender), 0);
    }
}
