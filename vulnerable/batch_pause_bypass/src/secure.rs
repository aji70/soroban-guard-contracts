//! SECURE: Batch Operations with Centralized Pause Check
//!
//! This is the fixed version of the batch pause bypass vulnerability.
//!
//! FIXES APPLIED:
//! 1. Centralized pause validation in internal transfer function
//! 2. All transfer operations (single and batch) use the same protected path
//! 3. No direct storage mutation bypasses pause checks

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Paused,
    Admin,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferOp {
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

#[contract]
pub struct SecureTokenContract;

#[contractimpl]
impl SecureTokenContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    pub fn pause(env: Env) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &true);
    }

    pub fn unpause(env: Env) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// ✅ FIX: Centralized pause check in internal function
    fn check_not_paused(env: &Env) {
        let paused: bool = env.storage().persistent().get(&DataKey::Paused).unwrap_or(false);
        if paused {
            panic!("contract is paused");
        }
    }

    /// ✅ FIX: Internal transfer function with mandatory pause check
    fn internal_transfer(env: &Env, from: Address, to: Address, amount: i128) {
        // ✅ Centralized pause validation - cannot be bypassed
        Self::check_not_paused(env);

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        if from_balance < amount {
            panic!("insufficient balance");
        }

        env.storage().persistent().set(&from_key, &(from_balance - amount));
        env.storage().persistent().set(&to_key, &(to_balance + amount));

        env.events().publish((symbol_short!("transfer"),), (from, to, amount));
    }

    /// ✅ SECURE: Uses internal transfer function with pause check
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        Self::internal_transfer(&env, from, to, amount);
    }

    /// ✅ SECURE: Batch transfer uses same protected internal function
    pub fn batch_transfer(env: Env, operations: Vec<TransferOp>) {
        // ✅ FIX: Use internal_transfer for each operation to ensure pause check
        for op in operations.iter() {
            op.from.require_auth();
            // ✅ All transfers go through the same protected path
            Self::internal_transfer(&env, op.from.clone(), op.to.clone(), op.amount);
        }
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(account)).unwrap_or(0)
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage().persistent().get(&DataKey::Paused).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

    #[test]
    fn test_normal_transfer_works_when_not_paused() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.initialize(&admin);
        env.mock_all_auths();
        
        client.mint(&alice, &1000);
        client.transfer(&alice, &bob, &500);

        assert_eq!(client.balance(&alice), 500);
        assert_eq!(client.balance(&bob), 500);
    }

    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_transfer_fails_when_paused() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.initialize(&admin);
        env.mock_all_auths();
        
        client.mint(&alice, &1000);
        client.pause();
        
        // Should fail due to pause
        client.transfer(&alice, &bob, &500);
    }

    /// Demonstrates the fix: batch transfer also respects pause
    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_batch_transfer_respects_pause() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let charlie = Address::generate(&env);

        client.initialize(&admin);
        env.mock_all_auths();
        
        client.mint(&alice, &1000);
        client.mint(&bob, &500);
        
        // Pause the contract
        client.pause();
        assert!(client.is_paused());

        // ✅ FIX: Batch transfer now fails when paused
        let mut operations = Vec::new(&env);
        operations.push_back(TransferOp {
            from: alice.clone(),
            to: charlie.clone(),
            amount: 300,
        });
        operations.push_back(TransferOp {
            from: bob.clone(),
            to: charlie.clone(),
            amount: 200,
        });

        // Should fail due to pause check in internal_transfer
        client.batch_transfer(&operations);
    }

    #[test]
    fn test_batch_transfer_works_when_not_paused() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let charlie = Address::generate(&env);

        client.initialize(&admin);
        env.mock_all_auths();
        
        client.mint(&alice, &1000);
        client.mint(&bob, &500);

        let mut operations = Vec::new(&env);
        operations.push_back(TransferOp {
            from: alice.clone(),
            to: charlie.clone(),
            amount: 300,
        });
        operations.push_back(TransferOp {
            from: bob.clone(),
            to: charlie.clone(),
            amount: 200,
        });

        client.batch_transfer(&operations);

        assert_eq!(client.balance(&alice), 700);
        assert_eq!(client.balance(&bob), 300);
        assert_eq!(client.balance(&charlie), 500);
    }

    #[test]
    #[should_panic(expected = "insufficient balance")]
    fn test_batch_transfer_validates_balances() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTokenContract);
        let client = SecureTokenContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.initialize(&admin);
        env.mock_all_auths();
        
        client.mint(&alice, &100); // Only 100 tokens

        let mut operations = Vec::new(&env);
        operations.push_back(TransferOp {
            from: alice.clone(),
            to: bob.clone(),
            amount: 500, // Trying to transfer more than balance
        });

        client.batch_transfer(&operations);
    }
}