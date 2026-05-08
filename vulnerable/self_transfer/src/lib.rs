//! VULNERABLE: Self-Transfer Storage-Slot Collision
//!
//! A minimal token contract that intentionally omits the `from != to` guard in
//! `transfer`. When `from == to`, both `get_balance` calls read the same storage
//! slot, and the second `set_balance` overwrites the first, inflating the
//! sender's balance by `amount` instead of leaving it unchanged.
//!
//! VULNERABILITY: No `from != to` check — self-transfer corrupts balance via
//! storage-slot collision.

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
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    /// Mint `amount` tokens to `to`. No auth check — unprotected by design for test setup.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current.checked_add(amount).expect("mint overflow"));
    }

    /// Returns the current balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    /// VULNERABLE: transfers `amount` from `from` to `to` without checking `from != to`.
    /// When `from == to`, both reads resolve to the same slot; the second write overwrites
    /// the first, inflating the balance by `amount`.
    ///
    /// # Vulnerability
    /// Missing `assert!(from != to)`. Impact: unlimited balance inflation via self-transfer.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        // ❌ No from != to check — self-transfer corrupts balance
        let from_balance = get_balance(&env, &from);
        let to_balance = get_balance(&env, &to); // same slot as from_balance when from == to
        set_balance(&env, &from, from_balance.checked_sub(amount).expect("transfer underflow"));
        set_balance(&env, &to, to_balance.checked_add(amount).expect("transfer overflow")); // overwrites the subtraction
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_normal_transfer() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.mint(&bob, &100);

        client.transfer(&alice, &bob, &200);

        assert_eq!(client.balance(&alice), 300);
        assert_eq!(client.balance(&bob), 300);
    }

    /// Demonstrates the vulnerability: self-transfer inflates the balance.
    /// balance == 600 is evidence of the bug, not correct behaviour.
    #[test]
    fn test_self_transfer_inflates_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.transfer(&alice, &alice, &100);

        assert_eq!(client.balance(&alice), 600);
    }

    #[test]
    #[should_panic]
    fn test_transfer_requires_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &500);
        // No mock_all_auths — should panic on require_auth
        client.transfer(&alice, &bob, &100);
    }

    #[test]
    fn test_balance_defaults_to_zero() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);

        let fresh = Address::generate(&env);
        assert_eq!(client.balance(&fresh), 0);
    }
}
