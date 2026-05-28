//! VULNERABLE: Public Role Grant (Unauthenticated Operator Escalation)
//!
//! This crate is a focused Soroban fixture demonstrating a critical flaw:
//! an entrypoint grants operator powers without admin authorization.
//!
//! Any caller can call `vulnerable_entry` and become an operator, enabling
//! `operator_only_action()`.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Operator(Address),
}

#[contract]
pub struct PublicRoleGrant;

#[contractimpl]
impl PublicRoleGrant {
    /// Setup admin for test/fixture purposes.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// BUG: granting an operator role is public and unauthenticated.
    ///
    /// The `amount` parameter is intentionally unused; it exists only to
    /// match the vulnerability shape used by scanners.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        // BUG: granting an operator role is public and unauthenticated.
        // The fixture should make this unsafe path reachable and easy to scan.
        let _ = (env.clone(), actor.clone(), amount);

        // Record an event with a short symbol name for scanner readability.

        // No admin authorization check.
        env.storage()
            .persistent()
            .set(&DataKey::Operator(actor.clone()), &true);

        // Emit event after write (vulnerable path still writes state correctly,
        // but the bug is missing auth). This keeps the crate simple.
        env.events().publish((symbol_short!("ogv"),), (actor, amount));

    }

    /// Operator-only restricted functionality.
    pub fn operator_only_action(env: Env, caller: Address) -> i128 {
        // In normal contracts, `caller` would be inferred from auth context.
        // For fixture simplicity, we treat `caller` as the would-be signer.
        let is_operator: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Operator(caller.clone()))
            .unwrap_or(false);
        if !is_operator {
            panic!("not operator");
        }

        // Return a value to make success observable.
        1
    }

    /// Exposes whether an address currently has operator privileges.
    pub fn is_operator(env: Env, actor: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Operator(actor))
            .unwrap_or(false)
    }

    /// Convenience getter.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("admin not initialized")
    }
}

/// Minimal client wrapper for tests.
mod client {
    // Avoid `#[contractclient]` macro here; the unit-test harness can
    // interact with the contract directly by using the contract methods.
}

// Unit tests call contract methods directly; no auto-generated clients.






#[cfg(test)]
mod tests {

    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, PublicRoleGrant);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        // Call initialize as a contract so storage APIs are accessible.
        let _ = env.as_contract(&contract_id, || {
            PublicRoleGrant::initialize(env.clone(), admin.clone())
        });
        (env, admin, attacker)

    }


    #[test]
    fn test_vulnerable_path_allows_public_operator_escalation() {
        let (env, _admin, attacker) = setup();
        let contract_id = env.register_contract(None, PublicRoleGrant);

        // Attacker becomes operator without admin auth.
        env.as_contract(&contract_id, || {
            PublicRoleGrant::vulnerable_entry(env.clone(), attacker.clone(), 123)
        });

        let out = env.as_contract(&contract_id, || {
            PublicRoleGrant::operator_only_action(env.clone(), attacker.clone())
        });
        assert_eq!(out, 1);

        let is_op = env.as_contract(&contract_id, || {
            PublicRoleGrant::is_operator(env.clone(), attacker.clone())
        });
        assert!(is_op);

    }


    /// Boundary condition: amount == 0 should still grant operator on the
    /// vulnerable path (because it is unauthenticated and amount is unused).
    #[test]
    fn test_boundary_amount_zero_still_grants_operator_vulnerable() {
        let (_env, _admin, attacker) = setup();

        let contract_id = _env.register_contract(None, PublicRoleGrant);
        let _ = _env.as_contract(&contract_id, || {
            PublicRoleGrant::vulnerable_entry(_env.clone(), attacker.clone(), 0)
        });



        let is_op = _env.as_contract(&contract_id, || {
            PublicRoleGrant::is_operator(_env.clone(), attacker.clone())
        });
        assert!(is_op);

        // Operator-only action succeeds.
        let out = _env.as_contract(&contract_id, || {
            PublicRoleGrant::operator_only_action(_env.clone(), attacker.clone())
        });
        assert_eq!(out, 1);


    }

    /// Secure mirror is expected to require admin auth for operator grants.
    #[test]
    #[should_panic]
    fn test_secure_path_rejects_unauthenticated_operator_grant() {

        let env = Env::default();

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        // Initialize admin.
        crate::secure::SecureRoleGrant::initialize(env.clone(), admin);

        // Attacker tries to call secure grant without auth.
        // `admin.require_auth()` should abort the call.
        let _ = crate::secure::SecureRoleGrant::grant_operator_secure(env.clone(), attacker.clone(), 0);

        // If it didn't panic, ensure invariant is not met.
        assert!(!crate::secure::SecureRoleGrant::is_operator(env, attacker));

    }

    #[test]
    #[should_panic]
    fn test_secure_path_preserves_invariant_when_called_without_auth() {

        let env = Env::default();
        let contract_id = env.register_contract(None, crate::secure::SecureRoleGrant);
        let client = crate::secure::SecureRoleGrantClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.initialize(&admin);

        // Ensure operator remains false.
        assert!(!client.is_operator(&attacker));

        // Attempting unauthorized grant should panic.
        client.grant_operator_secure(&attacker, &42);

        // (if it didn't panic) invariant would be violated
        assert!(!client.is_operator(&attacker));
    }
}


// Re-export secure module for tests.
pub mod secure {
    // Expose the mirror implementation to unit tests as a module.
    // The included file must not contain inner attributes like `#![no_std]`.
    include!("secure.rs");
}



