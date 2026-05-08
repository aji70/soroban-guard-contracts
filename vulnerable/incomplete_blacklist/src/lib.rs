//! VULNERABLE: Incomplete Blacklist
//!
//! The token contract maintains a blacklist of addresses that should be blocked
//! from transfers, but `transfer()` only checks whether the `to` address is
//! blacklisted. A blacklisted `from` address can still move tokens freely,
//! defeating the purpose of the blacklist and enabling laundering of restricted funds.
//!
//! VULNERABILITY: `transfer()` does not check whether `from` is blacklisted.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Blacklisted(Address),
}

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn blacklist(env: Env, account: Address) {
        env.storage()
            .persistent()
            .set(&DataKey::Blacklisted(account), &true);
    }

    /// VULNERABLE: only checks `to` — a blacklisted `from` can still transfer.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        // ❌ Missing: check from against the blacklist
        if env
            .storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::Blacklisted(to.clone()))
            .unwrap_or(false)
        {
            env.events().publish(
                (symbol_short!("blocked"),),
                (from.clone(), to.clone(), amount),
            );
            panic!("recipient is blacklisted");
        }

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage().persistent().set(&from_key, &(from_bal - amount));
        env.storage().persistent().set(&to_key, &(to_bal + amount));

        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

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

    fn setup() -> (Env, TokenContractClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &id);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        (env, client, alice, bob)
    }

    /// Demonstrates the bug: a blacklisted sender can still transfer.
    #[test]
    fn test_blacklisted_sender_can_transfer() {
        let (_env, client, alice, bob) = setup();
        client.mint(&alice, &1000);
        client.blacklist(&alice); // alice is blacklisted

        // BUG: this should panic but doesn't — from is never checked
        client.transfer(&alice, &bob, &500);

        assert_eq!(client.balance(&alice), 500);
        assert_eq!(client.balance(&bob), 500);
    }

    /// After the fix, a blacklisted sender's transfer must panic.
    #[test]
    #[should_panic]
    fn test_blacklisted_sender_is_blocked_after_fix() {
        let (_env, client, alice, bob) = setup();
        client.mint(&alice, &1000);
        client.blacklist(&alice);

        // This test documents the expected fixed behaviour.
        // With the current vulnerable code this does NOT panic (bug).
        // Once the fix is applied (check from as well), it will panic and this
        // test will pass.
        client.transfer(&alice, &bob, &500);
    }

    /// A non-blacklisted sender transferring to a blacklisted recipient panics.
    #[test]
    #[should_panic(expected = "recipient is blacklisted")]
    fn test_blacklisted_recipient_is_blocked() {
        let (_env, client, alice, bob) = setup();
        client.mint(&alice, &1000);
        client.blacklist(&bob); // bob is blacklisted recipient

        client.transfer(&alice, &bob, &500);
    }
}
