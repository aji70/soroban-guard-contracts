//! VULNERABLE: Self-Deposit Locks Tokens in the Contract
//!
//! A token contract that allows transfers to `env.current_contract_address()`.
//! Tokens sent there become permanently inaccessible because the contract does
//! not have a mechanism to spend its own balance.
//!
//! VULNERABILITY: `transfer()` and `transfer_from()` do not reject the
//! contract's own address as the destination.
//! SECURE MIRROR: `secure::SecureToken` rejects transfers to the contract
//! address before any auth or storage access.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address),
}

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

#[contract]
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let from_balance = get_balance(&env, &from);
        let to_balance = get_balance(&env, &to);
        set_balance(&env, &from, from_balance - amount);
        set_balance(&env, &to, to_balance + amount);
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");

        let from_balance = get_balance(&env, &from);
        assert!(from_balance >= amount, "insufficient balance");

        set_allowance(&env, &from, &spender, allowance - amount);
        set_balance(&env, &from, from_balance - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_transfer_to_contract_address_succeeds_in_vulnerable_contract() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);
        let alice = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.transfer(&alice, &contract_id, &100);

        assert_eq!(client.balance(&alice), 400);
        assert_eq!(client.balance(&contract_id), 100);
    }

    #[test]
    #[should_panic(expected = "cannot transfer to contract itself")]
    fn test_secure_transfer_to_contract_address_panics() {
        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureToken);
        let client = secure::SecureTokenClient::new(&env, &contract_id);
        let alice = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.transfer(&alice, &contract_id, &100);
    }

    #[test]
    fn test_secure_normal_transfer_is_unchanged() {
        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureToken);
        let client = secure::SecureTokenClient::new(&env, &contract_id);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.transfer(&alice, &bob, &125);

        assert_eq!(client.balance(&alice), 375);
        assert_eq!(client.balance(&bob), 125);
    }

    #[test]
    #[should_panic(expected = "cannot transfer to contract itself")]
    fn test_secure_transfer_from_to_contract_address_panics() {
        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureToken);
        let client = secure::SecureTokenClient::new(&env, &contract_id);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&owner, &500);
        client.approve(&owner, &spender, &200);
        client.transfer_from(&spender, &owner, &contract_id, &100);
    }
}
