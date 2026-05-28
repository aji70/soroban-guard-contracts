//! VULNERABLE: Wrapped Asset Allowlist Bypass
//!
//! A vault maintains an allowlist of approved *base* token addresses.
//! The `deposit` function accepts a `wrapper` address and checks only whether
//! the wrapper itself is on the allowlist — it never resolves or validates the
//! wrapper's underlying asset.
//!
//! A malicious actor can deploy a fake wrapper that claims any underlying token
//! and deposit unsupported assets into the vault.
//!
//! VULNERABILITY: Wrapper identity checked instead of underlying asset.
//! Severity: High
//!
//! Secure mirror: `src/secure.rs` — pins the underlying asset at wrapper
//! registration time and re-verifies it on every deposit.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    /// Allowlisted base token addresses.
    AllowedToken(Address),
    /// Registered wrappers: wrapper_addr → underlying_asset (stored at registration).
    WrapperAsset(Address),
    /// Depositor balance inside the vault.
    Balance(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Admin adds a base token to the allowlist.
    pub fn allow_token(env: Env, token: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::AllowedToken(token), &true);
    }

    /// Anyone can register a wrapper and declare its underlying asset.
    /// The vault stores the mapping but does NOT verify the underlying is allowed.
    pub fn register_wrapper(env: Env, wrapper: Address, underlying: Address) {
        env.storage()
            .persistent()
            .set(&DataKey::WrapperAsset(wrapper), &underlying);
    }

    /// VULNERABLE: checks whether the *wrapper* address is on the allowlist,
    /// not whether its underlying asset is approved.
    ///
    /// An attacker registers a fake wrapper pointing to an unsupported token,
    /// then adds the wrapper itself to the allowlist (or exploits a path where
    /// the wrapper address happens to match an allowed token address).
    ///
    /// In the minimal fixture the admin mistakenly allowlists the wrapper
    /// address directly, which is the realistic misconfiguration this pattern
    /// enables.
    pub fn deposit(env: Env, actor: Address, wrapper: Address, amount: i128) {
        actor.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        // ❌ BUG: checks wrapper identity, not the underlying asset.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::AllowedToken(wrapper.clone()))
            .unwrap_or(false);
        if !approved {
            panic!("token not allowed");
        }

        let key = DataKey::Balance(actor.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    pub fn allowed_tokens(env: Env) -> Vec<Address> {
        // Minimal helper used in tests — returns nothing; tests inspect storage directly.
        let _ = env;
        Vec::new(&env)
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
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableVault);
        let admin = Address::generate(&env);
        let approved_token = Address::generate(&env);
        VulnerableVaultClient::new(&env, &contract_id).initialize(&admin);
        VulnerableVaultClient::new(&env, &contract_id).allow_token(&approved_token);
        (env, contract_id, admin, approved_token)
    }

    /// Legitimate deposit with an approved base token succeeds.
    #[test]
    fn test_legitimate_deposit_succeeds() {
        let (env, contract_id, _admin, approved_token) = setup();
        let client = VulnerableVaultClient::new(&env, &contract_id);
        let actor = Address::generate(&env);

        // Register wrapper whose underlying IS the approved token.
        let wrapper = Address::generate(&env);
        client.register_wrapper(&wrapper, &approved_token);

        // Admin also allowlists the approved_token directly (normal path).
        client.deposit(&actor, &approved_token, &1000);
        assert_eq!(client.balance(&actor), 1000);
    }

    /// Demonstrates the vulnerability: a fake wrapper for an unsupported token
    /// is allowlisted by address, bypassing the underlying-asset check.
    #[test]
    fn test_fake_wrapper_bypasses_allowlist() {
        let (env, contract_id, _admin, _approved_token) = setup();
        let client = VulnerableVaultClient::new(&env, &contract_id);

        let unsupported_token = Address::generate(&env);
        let fake_wrapper = Address::generate(&env);
        let actor = Address::generate(&env);

        // Attacker registers a wrapper pointing to an unsupported token.
        client.register_wrapper(&fake_wrapper, &unsupported_token);

        // Admin (or attacker with admin rights) mistakenly allowlists the
        // *wrapper* address instead of the underlying token.
        client.allow_token(&fake_wrapper);

        // ❌ Deposit succeeds even though the underlying asset is not approved.
        client.deposit(&actor, &fake_wrapper, &500);
        assert_eq!(client.balance(&actor), 500);
    }

    /// Boundary: deposit with a wrapper whose underlying is not allowed and
    /// the wrapper itself is not on the allowlist is correctly rejected.
    #[test]
    #[should_panic(expected = "token not allowed")]
    fn test_unregistered_wrapper_rejected() {
        let (env, contract_id, _admin, _approved_token) = setup();
        let client = VulnerableVaultClient::new(&env, &contract_id);
        let actor = Address::generate(&env);
        let random_wrapper = Address::generate(&env);
        client.deposit(&actor, &random_wrapper, &100);
    }

    /// Secure version rejects a deposit when the wrapper's underlying asset
    /// is not on the allowlist, even if the wrapper address itself is allowed.
    #[test]
    #[should_panic(expected = "underlying asset not allowed")]
    fn test_secure_rejects_unsupported_underlying() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureVault);
        let admin = Address::generate(&env);
        let approved_token = Address::generate(&env);
        let unsupported_token = Address::generate(&env);
        let fake_wrapper = Address::generate(&env);
        let actor = Address::generate(&env);

        let client = SecureVaultClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.allow_token(&approved_token);

        // Register wrapper pointing to an unsupported underlying.
        client.register_wrapper(&fake_wrapper, &unsupported_token);

        // ✅ Secure vault panics because the underlying is not approved.
        client.deposit(&actor, &fake_wrapper, &500);
    }

    /// Secure version accepts a deposit when the wrapper's underlying IS allowed.
    #[test]
    fn test_secure_accepts_valid_wrapper() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureVault);
        let admin = Address::generate(&env);
        let approved_token = Address::generate(&env);
        let valid_wrapper = Address::generate(&env);
        let actor = Address::generate(&env);

        let client = SecureVaultClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.allow_token(&approved_token);
        client.register_wrapper(&valid_wrapper, &approved_token);

        client.deposit(&actor, &valid_wrapper, &300);
        assert_eq!(client.balance(&actor), 300);
    }
}
