#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

pub mod secure;

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    // VULNERABLE: The payout token is directly supplied by the caller.
    // There is no validation that this token is authorized for withdrawal.
    pub fn withdraw(env: Env, caller: Address, payout_token: Address, amount: i128) {
        caller.require_auth();
        
        let token_client = soroban_sdk::token::Client::new(&env, &payout_token);
        token_client.transfer(&env.current_contract_address(), &caller, &amount);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, token};
    use crate::secure::{SecureContract, SecureContractClient};

    // Helper to create a token
    fn create_token(env: &Env, admin: &Address) -> token::Client {
        token::Client::new(env, &env.register_stellar_asset_contract(admin.clone()))
    }

    #[test]
    fn test_vulnerable_withdraw_drains_valuable_token() {
        let env = Env::default();
        let admin = Address::generate(&env);
        
        let token_a = create_token(&env, &admin); // "Low value"
        let token_b = create_token(&env, &admin); // "High value"
        
        let contract_id = env.register_contract(None, VulnerableContract);
        
        // Fund the contract with both tokens
        token_a.mint(&env.current_contract_address(), &1000);
        token_b.mint(&env.current_contract_address(), &1000);
        
        let alice = Address::generate(&env);
        
        // Act: Attacker calls withdraw, asking for token_b instead of token_a
        let client = VulnerableContractClient::new(&env, &contract_id);
        client.withdraw(&alice, &token_b.address, &500);
        
        assert_eq!(token_a.balance(&env.current_contract_address()), 1000);
        assert_eq!(token_b.balance(&env.current_contract_address()), 500); // Stolen!
        assert_eq!(token_b.balance(&alice), 500);
    }

    #[test]
    fn test_secure_withdraw_only_allows_configured_token() {
        let env = Env::default();
        let admin = Address::generate(&env);
        
        let token_a = create_token(&env, &admin); // "Low value"
        let token_b = create_token(&env, &admin); // "High value"
        
        let contract_id = env.register_contract(None, SecureContract);
        let client = SecureContractClient::new(&env, &contract_id);
        
        // Configure to only allow token_a
        client.init(&token_a.address);
        
        // Fund the contract
        token_a.mint(&env.current_contract_address(), &1000);
        token_b.mint(&env.current_contract_address(), &1000);
        
        let alice = Address::generate(&env);
        
        // Act: Withdraw from secure contract
        client.withdraw(&alice, &500);
        
        assert_eq!(token_a.balance(&env.current_contract_address()), 500);
        assert_eq!(token_b.balance(&env.current_contract_address()), 1000); // Not stolen!
    }
}
