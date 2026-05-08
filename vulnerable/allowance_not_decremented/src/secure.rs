//! SECURE: Allowance Decremented After transfer_from
//!
//! Identical API to VulnerableToken but `transfer_from` decrements the
//! spender's allowance by `amount` before executing the transfer.

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

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &spender, amount);
    }

    /// ✅ Decrements allowance before transferring — spender cannot reuse it.
    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");
        // ✅ Decrement allowance first.
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
        client.approve(&owner, &spender, &300);
        (env, client, owner, spender, recipient)
    }

    /// transfer_from succeeds and allowance is decremented.
    #[test]
    fn test_transfer_from_decrements_allowance() {
        let (_env, client, owner, spender, recipient) = setup();
        client.transfer_from(&spender, &owner, &recipient, &300);
        assert_eq!(client.balance(&owner), 700);
        assert_eq!(client.balance(&recipient), 300);
        // Allowance is now zero.
        assert_eq!(client.allowance(&owner, &spender), 0);
    }

    /// Second transfer_from panics — allowance was consumed.
    #[test]
    #[should_panic(expected = "insufficient allowance")]
    fn test_second_transfer_from_rejected() {
        let (_env, client, owner, spender, recipient) = setup();
        client.transfer_from(&spender, &owner, &recipient, &300);
        // Allowance is 0 — this must panic.
        client.transfer_from(&spender, &owner, &recipient, &300);
    }
}
