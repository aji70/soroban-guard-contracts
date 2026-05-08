//! VULNERABLE: No Expiry on Admin Delegation
//!
//! A contract that supports temporary admin delegation. The delegate address
//! is stored along with an `expiry_ledger`, but `require_admin_or_delegate`
//! never checks whether the current ledger sequence has passed the expiry.
//! The delegated admin retains power indefinitely.
//!
//! VULNERABILITY: Missing `assert!(env.ledger().sequence() <= expiry_ledger)`
//! inside `require_admin_or_delegate`.
//! Severity: High
//!
//! Secure mirror: `secure::SecureAdminContract` checks expiry before accepting
//! delegate auth.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Delegate,
    DelegateExpiry,
    Value,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableAdminContract;

#[contractimpl]
impl VulnerableAdminContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Delegate admin rights to `delegate` until `expiry_ledger`.
    /// The expiry is stored but never enforced.
    pub fn delegate_admin(env: Env, delegate: Address, expiry_ledger: u32) {
        Self::require_admin(&env);
        env.storage().persistent().set(&DataKey::Delegate, &delegate);
        // Stored but never read back during auth checks — the vulnerability.
        env.storage().persistent().set(&DataKey::DelegateExpiry, &expiry_ledger);
    }

    /// A privileged action gated by admin-or-delegate.
    pub fn set_value(env: Env, value: u32) {
        Self::require_admin_or_delegate(&env);
        env.storage().persistent().set(&DataKey::Value, &value);
    }

    pub fn get_value(env: Env) -> u32 {
        env.storage().persistent().get(&DataKey::Value).unwrap_or(0)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }

    fn require_admin_or_delegate(env: &Env) {
        // Try delegate first.
        if let Some(delegate) = env
            .storage()
            .persistent()
            .get::<DataKey, Address>(&DataKey::Delegate)
        {
            // ❌ Missing expiry check:
            // let expiry: u32 = env.storage().persistent().get(&DataKey::DelegateExpiry).unwrap();
            // assert!(env.ledger().sequence() <= expiry, "delegation expired");
            delegate.require_auth();
            return;
        }
        Self::require_admin(env);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAdminContract);
        let admin = Address::generate(&env);
        let delegate = Address::generate(&env);
        VulnerableAdminContractClient::new(&env, &id).initialize(&admin);
        (env, id, admin, delegate)
    }

    /// Delegate can act within the intended window.
    #[test]
    fn test_delegate_can_act_within_window() {
        let (env, id, _admin, delegate) = setup();
        let client = VulnerableAdminContractClient::new(&env, &id);

        // Delegate until ledger 100; current sequence is 0.
        client.delegate_admin(&delegate, &100);
        client.set_value(&42);
        assert_eq!(client.get_value(), 42);
    }

    /// DEMONSTRATES VULNERABILITY: delegate can still act after expiry ledger has passed.
    #[test]
    fn test_delegate_acts_after_expiry_vulnerability() {
        let (env, id, _admin, delegate) = setup();
        let client = VulnerableAdminContractClient::new(&env, &id);

        // Delegate expires at ledger 5.
        client.delegate_admin(&delegate, &5);

        // Advance ledger well past expiry.
        env.ledger().set_sequence_number(1000);

        // Should be rejected but isn't — the vulnerability.
        client.set_value(&99);
        assert_eq!(
            client.get_value(),
            99,
            "delegate acted after expiry — vulnerability confirmed"
        );
    }

    /// Secure version rejects delegate after expiry.
    #[test]
    #[should_panic(expected = "delegation expired")]
    fn test_secure_rejects_delegate_after_expiry() {
        use crate::secure::SecureAdminContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureAdminContract);
        let admin = Address::generate(&env);
        let delegate = Address::generate(&env);
        let client = SecureAdminContractClient::new(&env, &id);

        client.initialize(&admin);
        client.delegate_admin(&delegate, &5);

        // Advance past expiry.
        env.ledger().set_sequence_number(1000);

        // Should panic.
        client.set_value(&99);
    }
}
