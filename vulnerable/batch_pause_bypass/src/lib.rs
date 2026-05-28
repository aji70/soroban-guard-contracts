//! VULNERABLE: Batch Operation Bypasses Pause Check
//!
//! A token contract that checks the paused flag in individual transfer functions,
//! but the bulk-transfer helper writes balances directly without pause validation.
//! During an emergency pause, attackers can still move funds through the batch entrypoint.
//!
//! VULNERABILITY: Batch operations bypass centralized pause checks by directly
//! mutating storage instead of using the protected transfer function.

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
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
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

    /// SECURE: Individual transfer checks pause status
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        
        // ✅ Pause check in individual transfer
        let paused: bool = env.storage().persistent().get(&DataKey::Paused).unwrap_or(false);
        if paused {
            panic!("contract is paused");
        }

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        env.storage().persistent().set(&from_key, &(from_balance - amount));
        env.storage().persistent().set(&to_key, &(to_balance + amount));

        env.events().publish((symbol_short!("transfer"),), (from, to, amount));
    }

    /// VULNERABLE: Batch transfer bypasses pause check
    pub fn batch_transfer(env: Env, operations: Vec<TransferOp>) {
        // ❌ BUG: No pause check in batch operation
        // ❌ BUG: Directly mutates balances without using protected transfer function
        
        for op in operations.iter() {
            op.from.require_auth();
            
            let from_key = DataKey::Balance(op.from.clone());
            let to_key = DataKey::Balance(op.to.clone());

            let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
            let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

            // ❌ Direct storage mutation bypasses pause validation
            env.storage().persistent().set(&from_key, &(from_balance - op.amount));
            env.storage().persistent().set(&to_key, &(to_balance + op.amount));

            env.events().publish(
                (symbol_short!("transfer"),),
                (op.from.clone(), op.to.clone(), op.amount),
            );
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
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

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
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

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

    /// Demonstrates the vulnerability: batch transfer bypasses pause check
    #[test]
    fn test_batch_transfer_bypasses_pause() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

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

        // Individual transfer should fail
        let transfer_result = std::panic::catch_unwind(|| {
            client.transfer(&alice, &charlie, &100);
        });
        assert!(transfer_result.is_err());

        // ❌ VULNERABILITY: Batch transfer succeeds despite pause
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

        // Verify transfers went through despite pause
        assert_eq!(client.balance(&alice), 700);
        assert_eq!(client.balance(&bob), 300);
        assert_eq!(client.balance(&charlie), 500);
    }

    #[test]
    fn test_batch_transfer_works_when_not_paused() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TokenContract);
        let client = TokenContractClient::new(&env, &contract_id);

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
}