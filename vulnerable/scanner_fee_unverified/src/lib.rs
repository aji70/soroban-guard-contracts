//! VULNERABLE: Scanner Registration Fee Not Verified After Transfer
//!
//! A scanner registry that calls `token.transfer` for the registration fee but
//! never checks the contract's balance delta. Fee-on-transfer tokens silently
//! deliver less than the required fee, yet the scanner is still registered.
//!
//! VULNERABILITY: Registration assumes the token transfer paid the full fee.
//! Missing pre/post balance snapshot — `assert!(received >= REGISTRATION_FEE)`.
//!
//! SECURE MIRROR: `secure::SecureRegistry` snapshots the contract's token
//! balance before and after the transfer and rejects under-payment.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

/// Required registration fee in token units.
pub const REGISTRATION_FEE: i128 = 100;

// ── Token interface (cross-contract) ─────────────────────────────────────────

pub mod token {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "TokenClient")]
    pub trait Token {
        fn transfer(env: Env, from: Address, to: Address, amount: i128);
        fn balance(env: Env, id: Address) -> i128;
    }
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Token,
    Registered(Address),
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct ScannerRegistry;

#[contractimpl]
impl ScannerRegistry {
    pub fn initialize(env: Env, token: Address) {
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// VULNERABLE: calls `token.transfer` for `REGISTRATION_FEE` then registers
    /// the scanner unconditionally — no balance delta check.
    ///
    /// # Vulnerability
    /// Missing pre/post balance snapshot. A fee-on-transfer token delivers less
    /// than `REGISTRATION_FEE`, but the scanner is registered anyway.
    pub fn register_scanner(env: Env, scanner: Address) {
        scanner.require_auth();
        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);

        // ❌ Transfer called but received amount is never verified.
        token_client.transfer(&scanner, &env.current_contract_address(), &REGISTRATION_FEE);

        // ❌ Registered regardless of how much was actually received.
        env.storage()
            .persistent()
            .set(&DataKey::Registered(scanner), &true);
    }

    /// Returns whether `scanner` is registered.
    pub fn is_registered(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Registered(scanner))
            .unwrap_or(false)
    }

    /// Fixture entry matching the issue's vulnerable pattern signature.
    ///
    /// # Vulnerability
    /// BUG: registration assumes token transfer paid the full fee.
    /// The fixture makes this unsafe path reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);
        // BUG: transfer is called with caller-supplied `amount` and the result
        // is never checked — under-payment silently registers the scanner.
        token_client.transfer(&actor, &env.current_contract_address(), &amount);
        // ❌ No balance delta check before registering.
        env.storage()
            .persistent()
            .set(&DataKey::Registered(actor), &true);
    }
}

// ── Mock fee token (10% fee on every transfer) ────────────────────────────────

#[contracttype]
pub enum TokenKey {
    Balance(Address),
}

#[contract]
pub struct FeeToken;

#[contractimpl]
impl FeeToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = TokenKey::Balance(to);
        let cur: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(cur + amount));
    }

    /// Recipient receives only 90% of `amount`; 10% is burned as a fee.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let received = amount * 90 / 100;
        let from_key = TokenKey::Balance(from);
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");
        env.storage().persistent().set(&from_key, &(from_bal - amount));
        let to_key = TokenKey::Balance(to);
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage().persistent().set(&to_key, &(to_bal + received));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TokenKey::Balance(id))
            .unwrap_or(0)
    }
}

// ── Standard token (0% fee) ───────────────────────────────────────────────────

#[contract]
pub struct StandardToken;

#[contractimpl]
impl StandardToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = TokenKey::Balance(to);
        let cur: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(cur + amount));
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let from_key = TokenKey::Balance(from);
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");
        env.storage().persistent().set(&from_key, &(from_bal - amount));
        let to_key = TokenKey::Balance(to);
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage().persistent().set(&to_key, &(to_bal + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TokenKey::Balance(id))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureRegistryClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    // ── Vulnerable path ───────────────────────────────────────────────────────

    /// Demonstrates the vulnerability: a fee-on-transfer token delivers only 90
    /// of the 100-unit fee, yet the scanner is registered anyway.
    #[test]
    fn test_vulnerable_fee_token_registers_with_underpayment() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, FeeToken);
        let registry_id = env.register_contract(None, ScannerRegistry);
        let token_client = FeeTokenClient::new(&env, &token_id);
        let registry_client = ScannerRegistryClient::new(&env, &registry_id);

        registry_client.initialize(&token_id);

        let scanner = Address::generate(&env);
        // Mint exactly the required fee — after 10% deduction only 90 arrives.
        token_client.mint(&scanner, &REGISTRATION_FEE);

        // ❌ Vulnerable: scanner registered even though only 90 was received.
        registry_client.register_scanner(&scanner);

        assert!(registry_client.is_registered(&scanner));
        // Registry holds only 90, not the required 100.
        assert_eq!(token_client.balance(&registry_id), 90);
    }

    /// Boundary: paying exactly REGISTRATION_FEE with a fee token delivers less
    /// than required — accepted by vulnerable, must be rejected by secure.
    #[test]
    fn test_vulnerable_boundary_underpayment_accepted() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, FeeToken);
        let registry_id = env.register_contract(None, ScannerRegistry);
        let token_client = FeeTokenClient::new(&env, &token_id);
        let registry_client = ScannerRegistryClient::new(&env, &registry_id);

        registry_client.initialize(&token_id);

        let scanner = Address::generate(&env);
        token_client.mint(&scanner, &REGISTRATION_FEE);

        // ❌ Boundary underpayment (90 < 100) silently accepted.
        registry_client.register_scanner(&scanner);
        assert!(registry_client.is_registered(&scanner));
    }

    // ── Secure path ───────────────────────────────────────────────────────────

    /// Secure implementation rejects registration when a fee token delivers
    /// less than REGISTRATION_FEE.
    #[test]
    #[should_panic]
    fn test_secure_rejects_fee_token_underpayment() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, FeeToken);
        let registry_id = env.register_contract(None, secure::SecureRegistry);
        let token_client = FeeTokenClient::new(&env, &token_id);
        let registry_client = SecureRegistryClient::new(&env, &registry_id);

        registry_client.initialize(&token_id);

        let scanner = Address::generate(&env);
        token_client.mint(&scanner, &REGISTRATION_FEE);

        // ✅ Secure: panics — only 90 received, not the required 100.
        registry_client.register_scanner(&scanner);
    }

    /// Secure implementation accepts registration when the full fee is received.
    #[test]
    fn test_secure_accepts_full_payment() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, StandardToken);
        let registry_id = env.register_contract(None, secure::SecureRegistry);
        let token_client = StandardTokenClient::new(&env, &token_id);
        let registry_client = SecureRegistryClient::new(&env, &registry_id);

        registry_client.initialize(&token_id);

        let scanner = Address::generate(&env);
        token_client.mint(&scanner, &REGISTRATION_FEE);

        // ✅ Secure: standard token delivers full 100 — registration succeeds.
        registry_client.register_scanner(&scanner);
        assert!(registry_client.is_registered(&scanner));
        assert_eq!(token_client.balance(&registry_id), REGISTRATION_FEE);
    }
}
