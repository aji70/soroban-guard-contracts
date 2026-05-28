//! SECURE mirror: Require admin approval for token registration.
//!
//! Key fixes:
//! 1. Only admin can register tokens (prevents arbitrary registration)
//! 2. Check for duplicate symbols before registration
//! 3. Optionally verify metadata through token interface (if available)
//!
//! This prevents attackers from registering fake tokens with trusted symbols.

use crate::{DataKey, TokenMetadata};
use soroban_sdk::{contract, contractimpl, Address, Env, String, Vec};

#[contract]
pub struct SecureTokenRegistry;

#[contractimpl]
impl SecureTokenRegistry {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// ✅ Fixed: Only admin can register tokens.
    /// ✅ Fixed: Check for duplicate symbols to prevent confusion.
    pub fn register_token(
        env: Env,
        token_address: Address,
        symbol: String,
        decimals: u32,
    ) {
        // ✅ Require admin authorization
        Self::require_admin(&env);

        // ✅ Check if token is already registered
        if env.storage().persistent().has(&DataKey::Token(token_address.clone())) {
            panic!("token already registered");
        }

        // ✅ Check for duplicate symbols
        if Self::symbol_exists(&env, &symbol) {
            panic!("symbol already in use");
        }

        let metadata = TokenMetadata {
            token_address: token_address.clone(),
            symbol: symbol.clone(),
            decimals,
            registered_by: Self::get_admin(&env),
            timestamp: env.ledger().timestamp(),
        };

        env.storage()
            .persistent()
            .set(&DataKey::Token(token_address.clone()), &metadata);

        // Store symbol mapping for duplicate check
        env.storage()
            .persistent()
            .set(&DataKey::Symbol(symbol), &token_address);
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

    /// Admin can remove a token from the registry.
    pub fn remove_token(env: Env, token_address: Address) {
        Self::require_admin(&env);
        
        // Remove symbol mapping
        if let Some(metadata) = env.storage().persistent().get::<DataKey, TokenMetadata>(&DataKey::Token(token_address.clone())) {
            env.storage().persistent().remove(&DataKey::Symbol(metadata.symbol));
        }
        
        env.storage().persistent().remove(&DataKey::Token(token_address));
    }

    /// Check if a symbol is already registered.
    fn symbol_exists(env: &Env, symbol: &String) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Symbol(symbol.clone()))
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }

    fn get_admin(env: &Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
