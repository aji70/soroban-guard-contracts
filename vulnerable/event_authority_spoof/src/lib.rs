//! VULNERABLE: Event authority spoof — event authority field taken from
//! caller-supplied argument instead of the authenticated signer.
//!
//! A contract emits an action event that includes an `authority` field.
//! Because the field is populated from an untrusted argument, any caller can
//! pass a trusted admin address as the authority, causing indexers to
//! attribute the action to that admin even though a different account signed.
//!
//! VULNERABILITY: `execute()` emits `authority` from the `claimed_authority`
//! argument rather than from the authenticated `actor`.
//!
//! SECURE MIRROR: `secure::SecureContract` derives the event authority from
//! the authenticated signer and stored admin state only.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    Admin,
    ActionCount,
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    pub fn init(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: emits `claimed_authority` in the event instead of `actor`.
    ///
    /// # Vulnerability
    /// An attacker passes the admin address as `claimed_authority`. Indexers
    /// record the action as performed by the admin even though `actor` signed.
    pub fn execute(env: Env, actor: Address, amount: i128, claimed_authority: Address) {
        actor.require_auth();

        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ActionCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::ActionCount, &(count + 1));

        // ❌ Authority field comes from untrusted argument — can be spoofed.
        env.events().publish(
            (symbol_short!("execute"),),
            (claimed_authority, amount, count + 1),
        );
    }

    pub fn action_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ActionCount)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env, IntoVal,
    };

    /// Vulnerable path: attacker passes admin as claimed_authority; event
    /// records admin as the authority even though attacker signed.
    #[test]
    fn test_vulnerable_event_spoofs_admin_as_authority() {
        let env = Env::default();
        env.mock_all_auths();

        let id = env.register_contract(None, VulnerableContract);
        let contract = VulnerableContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        contract.init(&admin);

        // Attacker signs but passes admin as the claimed authority.
        contract.execute(&attacker, &500, &admin);

        assert_eq!(contract.action_count(), 1);

        // ❌ Event authority is admin, not attacker — indexer is misled.
        let events = env.events().all();
        let (_, _, data) = events.last().unwrap();
        // First element of the data tuple is the authority address.
        let emitted_authority = Address::from_val(&env, &data);
        assert_eq!(
            emitted_authority, admin,
            "event incorrectly attributes action to admin"
        );
        assert_ne!(
            emitted_authority, attacker,
            "real signer is absent from event"
        );
    }

    /// Boundary: even when actor == claimed_authority the flaw is structural —
    /// nothing prevents a different caller from supplying any address.
    #[test]
    fn test_vulnerable_accepts_any_address_as_authority() {
        let env = Env::default();
        env.mock_all_auths();

        let id = env.register_contract(None, VulnerableContract);
        let contract = VulnerableContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        let random = Address::generate(&env);
        contract.init(&admin);

        // Pass a completely unrelated address as authority — accepted with no error.
        contract.execute(&random, &100, &admin);
        assert_eq!(contract.action_count(), 1);
    }

    /// Secure path: event authority is always the authenticated actor.
    #[test]
    fn test_secure_event_emits_real_signer() {
        use crate::secure::SecureContractClient;

        let env = Env::default();
        env.mock_all_auths();

        let id = env.register_contract(None, secure::SecureContract);
        let contract = SecureContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        contract.init(&admin);

        // Attacker tries to pass admin as authority — ignored by secure contract.
        contract.execute(&attacker, &500);

        let events = env.events().all();
        let (_, _, data) = events.last().unwrap();
        let emitted_authority = Address::from_val(&env, &data);

        // ✅ Event authority is the real signer, not the spoofed admin.
        assert_eq!(emitted_authority, attacker);
        assert_ne!(emitted_authority, admin);
    }
}
