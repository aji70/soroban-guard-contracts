//! VULNERABLE: Missing `require_auth` in `accept_admin`
//!
//! A two-step admin transfer contract where `accept_admin()` reads the pending
//! admin from storage and writes them as the new admin — but **never calls
//! `pending.require_auth()`**. Any address can call `accept_admin()` and seize
//! control of the contract.
//!
//! VULNERABILITY: The pending admin never signs the acceptance — anyone can
//! finalise the transfer and take over admin privileges.
//!
//! SECURE MIRROR: `secure::SecureAdmin` calls `pending.require_auth()` before
//! promoting the pending address.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    PendingAdmin,
}

#[contract]
pub struct VulnerableAdmin;

#[contractimpl]
impl VulnerableAdmin {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Propose a new admin. Only the current admin may call this.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &new_admin);
        env.events()
            .publish((symbol_short!("proposed"),), (new_admin,));
    }

    /// Cancel a pending transfer. Only the current admin may call this.
    pub fn cancel_admin_transfer(env: Env) {
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        current.require_auth();
        env.storage().persistent().remove(&DataKey::PendingAdmin);
        env.events().publish((symbol_short!("cancel"),), (current,));
    }

    /// VULNERABLE: reads `PendingAdmin` and promotes them without requiring
    /// their authorisation. Any caller can seize admin ownership.
    ///
    /// # Vulnerability
    /// Missing `pending.require_auth()`.
    /// Impact: anyone can call this function and make themselves (or any
    /// pending address) the admin.
    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        // ❌ BUG: no require_auth on pending — any caller can finalise.
        env.storage().persistent().set(&DataKey::Admin, &pending);
        env.storage().persistent().remove(&DataKey::PendingAdmin);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    pub fn get_pending_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::PendingAdmin)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, MockAuth, MockAuthInvoke},
        Address, Env, IntoVal,
    };

    fn setup_env() -> (Env, Address, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableAdmin);
        let admin = Address::generate(&env);
        // initialize does not call require_auth, so no mock needed.
        VulnerableAdminClient::new(&env, &id).initialize(&admin);
        (env, id, admin)
    }

    /// Helper to auth only the current admin for proposals.
    fn auth_admin(env: &Env, contract_id: &Address, admin: &Address, new_admin: &Address) {
        env.mock_auths(&[MockAuth {
            address: admin,
            invoke: &MockAuthInvoke {
                contract: contract_id,
                fn_name: "propose_admin",
                args: (new_admin.clone(),).into_val(env),
                sub_invokes: &[],
            },
        }]);
    }

    /// Demonstrates the vulnerability: a random caller can call accept_admin
    /// and the pending address becomes admin without ever signing.
    #[test]
    fn test_anyone_can_finalise_transfer() {
        let (env, id, admin) = setup_env();
        let client = VulnerableAdminClient::new(&env, &id);
        let pending = Address::generate(&env);
        let random_caller = Address::generate(&env);

        // Admin proposes a new pending admin.
        auth_admin(&env, &id, &admin, &pending);
        client.propose_admin(&pending);
        assert_eq!(client.get_pending_admin(), Some(pending.clone()));

        // Random caller (not the pending admin) calls accept_admin.
        // No auth is needed because accept_admin never calls require_auth.
        // Prove it by NOT mocking any auth for pending or caller.
        client.accept_admin();

        // The pending address became admin — even though they never signed.
        assert_eq!(
            client.get_admin(),
            pending,
            "pending admin became admin without their authorisation"
        );
    }

    /// Boundary: without a proposal, accept_admin must panic.
    #[test]
    #[should_panic(expected = "no pending admin")]
    fn test_accept_without_proposal_panics() {
        let (env, id, _admin) = setup_env();
        let client = VulnerableAdminClient::new(&env, &id);
        client.accept_admin();
    }

    /// Secure version: accept_admin requires pending admin auth, so an
    /// attacker without the pending admin's signature is rejected.
    #[test]
    fn test_secure_rejects_caller_without_pending_auth() {
        use crate::secure::SecureAdminClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAdmin);
        let client = SecureAdminClient::new(&env, &id);
        let admin = Address::generate(&env);
        let pending = Address::generate(&env);
        let attacker = Address::generate(&env);

        // Only admin + attacker auths — pending has NOT authorised.
        env.mock_auths(&[
            MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "initialize",
                    args: (admin.clone(),).into_val(&env),
                    sub_invokes: &[],
                },
            },
            MockAuth {
                address: &admin,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "propose_admin",
                    args: (pending.clone(),).into_val(&env),
                    sub_invokes: &[],
                },
            },
            MockAuth {
                address: &attacker,
                invoke: &MockAuthInvoke {
                    contract: &id,
                    fn_name: "accept_admin",
                    args: ().into_val(&env),
                    sub_invokes: &[],
                },
            },
        ]);

        client.initialize(&admin);
        client.propose_admin(&pending);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.accept_admin();
        }));

        assert!(
            result.is_err(),
            "must reject when pending admin has not signed"
        );
        assert_eq!(client.get_admin(), admin, "admin must remain unchanged");
        assert_eq!(
            client.get_pending_admin(),
            Some(pending),
            "pending admin must remain intact"
        );
    }

    /// Secure version: pending admin can accept when they sign.
    #[test]
    fn test_secure_pending_admin_can_accept() {
        use crate::secure::SecureAdminClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureAdmin);
        let client = SecureAdminClient::new(&env, &id);
        let admin = Address::generate(&env);
        let pending = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.propose_admin(&pending);

        // Pending admin signs and accepts.
        client.accept_admin();
        assert_eq!(
            client.get_admin(),
            pending,
            "pending admin must be able to accept when authorised"
        );
    }
}
