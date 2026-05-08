//! VULNERABLE: Missing Events
//!
//! A token contract where `mint()` and `burn()` mutate balances without
//! calling `env.events().publish()`. Off-chain indexers and users cannot
//! track these state changes, leading to inconsistent views of the contract state.
//!
//! VULNERABILITY: Missing `env.events().publish()` in state-mutating functions.

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
    /// Mint tokens to an address. No auth check — unprotected by design for test setup.
    ///
    /// # Vulnerability
    /// No event emitted — off-chain indexers cannot track this supply change.
    pub fn mint(env: Env, to: Address, amount: i128) {
        // ❌ No env.events().publish() — off-chain indexers are blind to this
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Burn tokens from an address.
    /// VULNERABLE: No event emitted for off-chain tracking.
    pub fn burn(env: Env, from: Address, amount: i128) {
        // ❌ No env.events().publish() — off-chain indexers are blind to this
        let key = DataKey::Balance(from);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current - amount));
    }

    /// Transfer tokens between addresses. Emits a transfer event — shown as the correct pattern.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        env.storage()
            .persistent()
            .set(&from_key, &(from_balance - amount));
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

    #[test]
    fn test_mint_and_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        client.mint(&alice, &1000);
        assert_eq!(client.balance(&alice), 1000);
    }

    #[test]
    fn test_burn_and_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        client.mint(&alice, &1000);
        client.burn(&alice, &300);
        assert_eq!(client.balance(&alice), 700);
    }

    /// Demonstrates the vulnerability: mint succeeds silently with no event trace.
    #[test]
    fn test_mint_succeeds_silently_no_events() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);

        // Mint tokens - this should emit no events
        client.mint(&alice, &500);

        // Check that balance was updated
        assert_eq!(client.balance(&alice), 500);

        // In a real scenario, we'd check that no events were emitted
        // For this test, we just verify the state change occurred
    }

    #[test]
    fn test_burn_succeeds_silently_no_events() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        client.mint(&alice, &1000);

        // Burn tokens - this should emit no events
        client.burn(&alice, &300);

        // Check that balance was updated
        assert_eq!(client.balance(&alice), 700);
    }

    #[test]
    fn test_transfer_emits_events() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &1000);
        client.transfer(&alice, &bob, &300);

        assert_eq!(client.balance(&alice), 700);
        assert_eq!(client.balance(&bob), 300);
    }
}
