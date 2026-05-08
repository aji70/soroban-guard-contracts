//! SECURE: Self-Transfer Guard
//!
//! A secure mirror of the VulnerableToken contract. Identical API (`mint`,
//! `balance`, `transfer`) but `transfer` asserts `from != to` as its very
//! first operation — before `require_auth` and before any storage access —
//! preventing the storage-slot collision that inflates balances in the
//! vulnerable version.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

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

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current.checked_add(amount).expect("mint overflow"));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        // ✅ Guard fires before require_auth and any storage access
        assert!(from != to, "self-transfer not allowed");
        from.require_auth();
        let from_balance = get_balance(&env, &from);
        let to_balance = get_balance(&env, &to);
        set_balance(&env, &from, from_balance.checked_sub(amount).expect("transfer underflow"));
        set_balance(&env, &to, to_balance.checked_add(amount).expect("transfer overflow"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_normal_transfer() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.mint(&bob, &100);
        client.transfer(&alice, &bob, &200);

        assert_eq!(client.balance(&alice), 300);
        assert_eq!(client.balance(&bob), 300);
    }

    #[test]
    #[should_panic(expected = "self-transfer not allowed")]
    fn test_self_transfer_rejected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.transfer(&alice, &alice, &100);
    }

    #[test]
    #[should_panic]
    fn test_transfer_requires_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &500);
        // No mock_all_auths — should panic on require_auth
        client.transfer(&alice, &bob, &100);
    }

    #[test]
    fn test_balance_defaults_to_zero() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let fresh = Address::generate(&env);
        assert_eq!(client.balance(&fresh), 0);
    }
}
