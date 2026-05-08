//! VULNERABLE: Integer Underflow on Balance Subtraction
//!
//! A token contract where `transfer()` subtracts balances with raw `-` on
//! `i128`. If `amount > from_balance` the subtraction underflows, wrapping to
//! a large positive number and crediting the sender with a massive balance.
//!
//! VULNERABILITY: `from_balance - amount` with no underflow guard.
//! SECURE MIRROR:  `secure_vault` uses `checked_sub` and panics on underflow.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    /// Mint `amount` tokens to `to`. No auth check — for test setup.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// VULNERABLE: subtracts `amount` from `from_balance` with raw `-`.
    /// If `amount > from_balance` the i128 wraps to a large positive value.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        // ❌ Raw subtraction — wraps on underflow if amount > from_balance
        env.storage()
            .persistent()
            .set(&from_key, &from_balance.wrapping_sub(amount));
        env.storage()
            .persistent()
            .set(&to_key, &(to_balance + amount));

        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

    /// Returns the balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, soroban_sdk::Address, TokenContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);
        (env, contract_id, client)
    }

    #[test]
    fn test_normal_transfer() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &1000);
        client.transfer(&alice, &bob, &400);

        assert_eq!(client.balance(&alice), 600);
        assert_eq!(client.balance(&bob), 400);
    }

    /// Demonstrates the vulnerability: transferring more than the balance
    /// wraps the i128 instead of panicking.
    #[test]
    fn test_underflow_wraps() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &100);
        // Transfer 200 when balance is only 100 — underflows
        client.transfer(&alice, &bob, &200);

        // 100i128.wrapping_sub(200) == i128::MAX - 99
        assert_eq!(client.balance(&alice), 100i128.wrapping_sub(200));
        assert_eq!(client.balance(&bob), 200);
    }

    #[test]
    fn test_exact_balance_transfer() {
        let (env, _, client) = setup();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &500);
        client.transfer(&alice, &bob, &500);

        assert_eq!(client.balance(&alice), 0);
        assert_eq!(client.balance(&bob), 500);
    }
}
