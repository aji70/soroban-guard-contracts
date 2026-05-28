//! SECURE: Governance-gated plugin dispatcher.
//!
//! Plugins must be explicitly approved by the admin before they can be
//! executed. Any unapproved plugin address causes an immediate panic.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, Env};

#[contracttype]
pub enum SecureDataKey {
    Admin,
    Approved(Address),
    CallCount,
}

#[contracterror]
#[derive(Copy, Clone)]
pub enum DispatchError {
    NotApproved = 1,
    AlreadyInitialized = 2,
}

#[contract]
pub struct SecureDispatcher;

#[contractimpl]
impl SecureDispatcher {
    /// Initialize with a governance admin. Can only be called once.
    pub fn init(env: Env, admin: Address) {
        if env.storage().persistent().has(&SecureDataKey::Admin) {
            panic_with_error!(&env, DispatchError::AlreadyInitialized);
        }
        env.storage().persistent().set(&SecureDataKey::Admin, &admin);
    }

    /// Admin-only: add `plugin_id` to the approved set.
    pub fn approve_plugin(env: Env, admin: Address, plugin_id: Address) {
        let stored_admin: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        assert_eq!(admin, stored_admin, "not admin");
        env.storage()
            .persistent()
            .set(&SecureDataKey::Approved(plugin_id), &true);
    }

    /// SECURE: panics if `plugin_id` is not in the approved set.
    pub fn dispatch(env: Env, actor: Address, amount: i128, plugin_id: Address) {
        actor.require_auth();

        // ✅ Allowlist check before any external call.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Approved(plugin_id.clone()))
            .unwrap_or(false);
        if !approved {
            panic_with_error!(&env, DispatchError::NotApproved);
        }

        let _: () = env.invoke_contract(
            &plugin_id,
            &symbol_short!("execute"),
            soroban_sdk::vec![
                &env,
                actor.into_val(&env),
                amount.into_val(&env),
            ],
        );

        let count: u32 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::CallCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&SecureDataKey::CallCount, &(count + 1));
    }

    pub fn call_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&SecureDataKey::CallCount)
            .unwrap_or(0)
    }
}
