//! VULNERABLE: Fake Token Registration
//!
//! An asset registry that trusts caller-supplied symbol and decimals metadata.
//! Attackers can register fake assets that look identical to trusted tokens
//! in downstream views, enabling phishing attacks and user confusion.
//!
//! VULNERABILITY: Asset metadata (symbol, decimals) is stored from untrusted
//! caller arguments without verification against the actual token contract.
//! Severity: High
//!
//! Attack scenario:
//! 1. Attacker deploys a malicious token contract
//! 2. Attacker registers it with symbol="USDC" and decimals=6
//! 3. Users see "USDC" in the registry and trust it
//! 4. Users interact with the fake token, losing funds
//!
//! Secure fix: Require admin approval for token registration and verify
//! metadata through the token interface where possible.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

pub mod secure;

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenMetadata {
    pub token_address: Address,
    pub symbol: String,
    pub decimals: u32,
    pub registered_by: Address,
    pub timestamp: u64,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Token(Address), // Maps token address -> TokenMetadata
    Symbol(String), // Maps symbol -> token address (used in secure version)
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableTokenRegistry;

#[contractimpl]
impl VulnerableTokenRegistry {
    /// Initialize the registry with an admin address. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: Registers a token with caller-supplied metadata.
    /// ❌ BUG: No verification that the symbol and decimals match the actual
    /// token contract. An attacker can register a malicious token with a
    /// trusted symbol like "USDC" or "XLM".
    pub fn register_token(
        env: Env,
        token_address: Address,
        symbol: String,
        decimals: u32,
        caller: Address,
    ) {
        caller.require_auth();

        // ❌ Missing: Admin approval check
        // ❌ Missing: Verification of symbol/decimals against token contract
        // ❌ Missing: Check for duplicate symbols

        let metadata = TokenMetadata {
            token_address: token_address.clone(),
            symbol,
            decimals,
            registered_by: caller,
            timestamp: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Token(token_address), &metadata);
    }

    /// Returns the metadata for a registered token, or None if not found.
    pub fn get_token(env: Env, token_address: Address) -> Option<TokenMetadata> {
        env.storage()
            .persistent()
            .get(&DataKey::Token(token_address))
    }

    /// Returns true if a token is registered.
    pub fn is_registered(env: Env, token_address: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Token(token_address))
    }

    /// Admin can remove a token from the registry (e.g., after discovering it's fake).
    pub fn remove_token(env: Env, token_address: Address) {
        Self::require_admin(&env);
        env.storage().persistent().remove(&DataKey::Token(token_address));
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableTokenRegistry);
        let admin = Address::generate(&env);
        VulnerableTokenRegistryClient::new(&env, &contract_id).initialize(&admin);
        (env, contract_id, admin)
    }

    /// Demonstrates the vulnerability: an attacker registers a fake token
    /// with a trusted symbol (e.g., "USDC") and the registry accepts it.
    #[test]
    fn test_fake_token_registration_succeeds() {
        let (env, contract_id, _admin) = setup();
        let client = VulnerableTokenRegistryClient::new(&env, &contract_id);

        let attacker = Address::generate(&env);
        let fake_token = Address::generate(&env);

        // Attacker registers their malicious token as "USDC" with 6 decimals
        client.register_token(
            &fake_token,
            &String::from_str(&env, "USDC"),
            &6u32,
            &attacker,
        );

        // The fake token is now in the registry with trusted metadata
        let metadata = client.get_token(&fake_token).unwrap();
        assert_eq!(metadata.symbol, String::from_str(&env, "USDC"));
        assert_eq!(metadata.decimals, 6);
        assert_eq!(metadata.registered_by, attacker);
        assert!(client.is_registered(&fake_token));
    }

    /// Demonstrates that multiple tokens can be registered with the same symbol,
    /// creating confusion for users.
    #[test]
    fn test_duplicate_symbol_allowed() {
        let (env, contract_id, _admin) = setup();
        let client = VulnerableTokenRegistryClient::new(&env, &contract_id);

        let attacker1 = Address::generate(&env);
        let attacker2 = Address::generate(&env);
        let fake_token1 = Address::generate(&env);
        let fake_token2 = Address::generate(&env);

        // Both attackers register different tokens with the same symbol
        client.register_token(
            &fake_token1,
            &String::from_str(&env, "USDC"),
            &6u32,
            &attacker1,
        );
        client.register_token(
            &fake_token2,
            &String::from_str(&env, "USDC"),
            &6u32,
            &attacker2,
        );

        // Both fake tokens are registered with identical symbols
        let metadata1 = client.get_token(&fake_token1).unwrap();
        let metadata2 = client.get_token(&fake_token2).unwrap();
        assert_eq!(metadata1.symbol, metadata2.symbol);
        assert_eq!(metadata1.symbol, String::from_str(&env, "USDC"));
    }

    /// Demonstrates that anyone can register a token without admin approval.
    #[test]
    fn test_no_admin_approval_required() {
        let (env, contract_id, _admin) = setup();
        let client = VulnerableTokenRegistryClient::new(&env, &contract_id);

        let random_user = Address::generate(&env);
        let token = Address::generate(&env);

        // Any user can register a token
        client.register_token(
            &token,
            &String::from_str(&env, "SCAM"),
            &18u32,
            &random_user,
        );

        assert!(client.is_registered(&token));
    }

    /// Admin can remove a fake token after discovering it.
    #[test]
    fn test_admin_can_remove_token() {
        let (env, contract_id, _admin) = setup();
        let client = VulnerableTokenRegistryClient::new(&env, &contract_id);

        let attacker = Address::generate(&env);
        let fake_token = Address::generate(&env);

        client.register_token(
            &fake_token,
            &String::from_str(&env, "USDC"),
            &6u32,
            &attacker,
        );
        assert!(client.is_registered(&fake_token));

        // Admin removes the fake token
        client.remove_token(&fake_token);
        assert!(!client.is_registered(&fake_token));
        assert!(client.get_token(&fake_token).is_none());
    }

    /// Secure version requires admin approval for registration.
    #[test]
    #[should_panic(expected = "not initialized")]
    fn test_secure_requires_admin_approval() {
        use crate::secure::SecureTokenRegistryClient;

        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureTokenRegistry);
        let admin = Address::generate(&env);
        let random_user = Address::generate(&env);
        let token = Address::generate(&env);

        // Initialize with admin
        env.mock_all_auths();
        SecureTokenRegistryClient::new(&env, &contract_id).initialize(&admin);

        // Clear auths - now require_auth will enforce
        env.set_auths(&[]);

        // Random user tries to register a token - should panic
        SecureTokenRegistryClient::new(&env, &contract_id).register_token(
            &token,
            &String::from_str(&env, "SCAM"),
            &18u32,
        );
    }

    /// Secure version rejects duplicate symbols.
    #[test]
    #[should_panic(expected = "symbol already in use")]
    fn test_secure_rejects_duplicate_symbols() {
        use crate::secure::SecureTokenRegistryClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureTokenRegistry);
        let admin = Address::generate(&env);

        SecureTokenRegistryClient::new(&env, &contract_id).initialize(&admin);

        let token1 = Address::generate(&env);
        let token2 = Address::generate(&env);

        // Register first token with "USDC"
        SecureTokenRegistryClient::new(&env, &contract_id).register_token(
            &token1,
            &String::from_str(&env, "USDC"),
            &6u32,
        );

        // Try to register second token with same symbol - should panic
        SecureTokenRegistryClient::new(&env, &contract_id).register_token(
            &token2,
            &String::from_str(&env, "USDC"),
            &6u32,
        );
    }

    /// Secure version allows admin to register legitimate tokens.
    #[test]
    fn test_secure_admin_can_register() {
        use crate::secure::SecureTokenRegistryClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureTokenRegistry);
        let admin = Address::generate(&env);

        SecureTokenRegistryClient::new(&env, &contract_id).initialize(&admin);

        let token = Address::generate(&env);

        // Admin registers a legitimate token
        SecureTokenRegistryClient::new(&env, &contract_id).register_token(
            &token,
            &String::from_str(&env, "USDC"),
            &6u32,
        );

        let metadata = SecureTokenRegistryClient::new(&env, &contract_id)
            .get_token(&token)
            .unwrap();
        assert_eq!(metadata.symbol, String::from_str(&env, "USDC"));
        assert_eq!(metadata.decimals, 6);
        assert_eq!(metadata.registered_by, admin);
    }
}
