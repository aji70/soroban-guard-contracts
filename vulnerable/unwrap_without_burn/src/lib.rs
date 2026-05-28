//! VULNERABLE: Unwrap Without Burn
//!
//! A wrapper token contract that releases underlying tokens during unwrap but
//! forgets to burn wrapper shares. Users can repeatedly unwrap the same shares
//! and drain the custody contract.
//!
//! VULNERABILITY: The `unwrap` function transfers underlying tokens to the user
//! but does not decrement or burn the wrapper token balance. This allows users
//! to call unwrap multiple times with the same wrapper shares.
//! Severity: Critical
//!
//! Attack scenario:
//! 1. User deposits 100 underlying tokens, receives 100 wrapper shares
//! 2. User calls unwrap(100) → receives 100 underlying tokens
//! 3. User still has 100 wrapper shares (not burned!)
//! 4. User calls unwrap(100) again → receives another 100 underlying tokens
//! 5. Repeat until custody is drained
//!
//! Secure fix: Burn or decrement wrapper shares before transferring underlying tokens.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    UnderlyingToken,      // Address of the underlying token
    WrapperBalance(Address), // Wrapper token balance per user
    TotalSupply,          // Total wrapper token supply
    CustodyBalance,       // Amount of underlying tokens held in custody
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableWrapper;

#[contractimpl]
impl VulnerableWrapper {
    /// Initialize the wrapper with the underlying token address.
    pub fn initialize(env: Env, underlying_token: Address) {
        if env.storage().persistent().has(&DataKey::UnderlyingToken) {
            panic!("already initialized");
        }
        env.storage()
            .persistent()
            .set(&DataKey::UnderlyingToken, &underlying_token);
        env.storage().persistent().set(&DataKey::TotalSupply, &0i128);
        env.storage().persistent().set(&DataKey::CustodyBalance, &0i128);
    }

    /// Wrap underlying tokens: user deposits underlying, receives wrapper shares.
    pub fn wrap(env: Env, user: Address, amount: i128) {
        user.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        let underlying_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::UnderlyingToken)
            .expect("not initialized");

        // Transfer underlying tokens from user to this contract
        let token_client = token::TokenClient::new(&env, &underlying_token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        // Mint wrapper shares to user
        let balance_key = DataKey::WrapperBalance(user.clone());
        let current_balance: i128 = env
            .storage()
            .persistent()
            .get(&balance_key)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        // Update total supply and custody balance
        let total_supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(total_supply + amount));

        let custody: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CustodyBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::CustodyBalance, &(custody + amount));
    }

    /// VULNERABLE: Unwrap wrapper tokens to receive underlying tokens.
    /// ❌ BUG: Transfers underlying tokens but does NOT burn wrapper shares.
    /// Users can call this repeatedly with the same wrapper balance.
    pub fn unwrap(env: Env, user: Address, amount: i128) {
        user.require_auth();

        if amount <= 0 {
            panic!("amount must be positive");
        }

        // Check user has enough wrapper balance
        let balance_key = DataKey::WrapperBalance(user.clone());
        let current_balance: i128 = env
            .storage()
            .persistent()
            .get(&balance_key)
            .unwrap_or(0);

        if current_balance < amount {
            panic!("insufficient wrapper balance");
        }

        // Check custody has enough underlying tokens
        let custody: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CustodyBalance)
            .unwrap_or(0);

        if custody < amount {
            panic!("insufficient custody balance");
        }

        let underlying_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::UnderlyingToken)
            .expect("not initialized");

        // ❌ BUG: Transfer underlying tokens WITHOUT burning wrapper shares
        let token_client = token::TokenClient::new(&env, &underlying_token);
        token_client.transfer(&env.current_contract_address(), &user, &amount);

        // Update custody balance
        env.storage()
            .persistent()
            .set(&DataKey::CustodyBalance, &(custody - amount));

        // ❌ MISSING: Burn wrapper shares
        // env.storage().persistent().set(&balance_key, &(current_balance - amount));
        // let total_supply: i128 = env.storage().persistent().get(&DataKey::TotalSupply).unwrap_or(0);
        // env.storage().persistent().set(&DataKey::TotalSupply, &(total_supply - amount));
    }

    /// Get wrapper token balance for a user.
    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::WrapperBalance(user))
            .unwrap_or(0)
    }

    /// Get total wrapper token supply.
    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    /// Get custody balance (underlying tokens held by contract).
    pub fn custody_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CustodyBalance)
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, AuthorizedFunction, AuthorizedInvocation},
        Address, Env, IntoVal, Symbol,
    };

    fn create_token_contract<'a>(env: &Env, admin: &Address) -> (Address, token::TokenClient<'a>) {
        let contract_id = env.register_stellar_asset_contract(admin.clone());
        (
            contract_id.clone(),
            token::TokenClient::new(env, &contract_id),
        )
    }

    fn setup() -> (Env, Address, Address, Address, token::TokenClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        // Create underlying token
        let (token_id, token_client) = create_token_contract(&env, &admin);

        // Mint underlying tokens to user
        token_client.mint(&user, &1000);

        // Deploy wrapper contract
        let wrapper_id = env.register_contract(None, VulnerableWrapper);

        VulnerableWrapperClient::new(&env, &wrapper_id).initialize(&token_id);

        (env, wrapper_id, user, token_id, token_client)
    }

    /// Demonstrates the vulnerability: user wraps once, unwraps twice with same shares.
    #[test]
    fn test_double_unwrap_succeeds() {
        let (env, wrapper_id, user, _token_id, token_client) = setup();
        let client = VulnerableWrapperClient::new(&env, &wrapper_id);

        // User wraps 100 tokens
        client.wrap(&user, &100);

        assert_eq!(client.balance(&user), 100);
        assert_eq!(client.custody_balance(), 100);
        assert_eq!(token_client.balance(&user), 900); // 1000 - 100

        // First unwrap: user gets 100 underlying tokens back
        client.unwrap(&user, &100);

        // ❌ BUG: User still has 100 wrapper shares (not burned!)
        assert_eq!(client.balance(&user), 100);
        assert_eq!(client.custody_balance(), 0);
        assert_eq!(token_client.balance(&user), 1000); // Got 100 back

        // Wrap again to refill custody
        client.wrap(&user, &100);
        assert_eq!(client.custody_balance(), 100);

        // Second unwrap with SAME wrapper shares: succeeds again!
        client.unwrap(&user, &100);

        // User has drained custody twice with same wrapper shares
        assert_eq!(client.balance(&user), 100); // Still has wrapper shares!
        assert_eq!(client.custody_balance(), 0);
        assert_eq!(token_client.balance(&user), 1000); // Got another 100
    }

    /// Demonstrates repeated unwrapping drains the custody.
    #[test]
    fn test_repeated_unwrap_drains_custody() {
        let (env, wrapper_id, user, _token_id, token_client) = setup();
        let client = VulnerableWrapperClient::new(&env, &wrapper_id);

        // User wraps 100 tokens
        client.wrap(&user, &100);
        assert_eq!(client.balance(&user), 100);
        assert_eq!(token_client.balance(&user), 900);

        // Unwrap 50 tokens
        client.unwrap(&user, &50);

        // ❌ User still has 100 wrapper shares (should have 50)
        assert_eq!(client.balance(&user), 100);
        assert_eq!(client.custody_balance(), 50);
        assert_eq!(token_client.balance(&user), 950);

        // Unwrap another 50 with the same wrapper shares
        client.unwrap(&user, &50);

        // Custody is now empty, but user still has 100 wrapper shares
        assert_eq!(client.balance(&user), 100);
        assert_eq!(client.custody_balance(), 0);
        assert_eq!(token_client.balance(&user), 1000);
    }

    /// Normal wrap operation works correctly.
    #[test]
    fn test_wrap_works() {
        let (env, wrapper_id, user, _token_id, token_client) = setup();
        let client = VulnerableWrapperClient::new(&env, &wrapper_id);

        client.wrap(&user, &100);

        assert_eq!(client.balance(&user), 100);
        assert_eq!(client.total_supply(), 100);
        assert_eq!(client.custody_balance(), 100);
        assert_eq!(token_client.balance(&user), 900);
    }

    /// Secure version burns wrapper shares, preventing double unwrap.
    #[test]
    #[should_panic(expected = "insufficient wrapper balance")]
    fn test_secure_prevents_double_unwrap() {
        use crate::secure::{SecureWrapper, SecureWrapperClient};

        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        let (token_id, token_client) = create_token_contract(&env, &admin);
        token_client.mint(&user, &1000);

        let wrapper_id = env.register_contract(None, SecureWrapper);
        SecureWrapperClient::new(&env, &wrapper_id).initialize(&token_id);

        let client = SecureWrapperClient::new(&env, &wrapper_id);

        // Wrap 100 tokens
        client.wrap(&user, &100);
        assert_eq!(client.balance(&user), 100);

        // First unwrap: burns wrapper shares
        client.unwrap(&user, &100);
        assert_eq!(client.balance(&user), 0); // ✅ Shares burned

        // Second unwrap: should panic (insufficient balance)
        client.unwrap(&user, &100);
    }

    /// Secure version correctly decrements wrapper balance.
    #[test]
    fn test_secure_burns_shares_correctly() {
        use crate::secure::{SecureWrapper, SecureWrapperClient};

        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        let (token_id, token_client) = create_token_contract(&env, &admin);
        token_client.mint(&user, &1000);

        let wrapper_id = env.register_contract(None, SecureWrapper);
        SecureWrapperClient::new(&env, &wrapper_id).initialize(&token_id);

        let client = SecureWrapperClient::new(&env, &wrapper_id);

        // Wrap 100 tokens
        client.wrap(&user, &100);
        assert_eq!(client.balance(&user), 100);
        assert_eq!(client.total_supply(), 100);

        // Unwrap 60 tokens
        client.unwrap(&user, &60);

        // ✅ Wrapper balance correctly decremented
        assert_eq!(client.balance(&user), 40);
        assert_eq!(client.total_supply(), 40);
        assert_eq!(client.custody_balance(), 40);
        assert_eq!(token_client.balance(&user), 960);

        // Can only unwrap remaining 40
        client.unwrap(&user, &40);
        assert_eq!(client.balance(&user), 0);
        assert_eq!(client.total_supply(), 0);
        assert_eq!(token_client.balance(&user), 1000);
    }
}
