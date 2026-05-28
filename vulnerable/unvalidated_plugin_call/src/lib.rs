//! VULNERABLE: Unvalidated plugin call — dispatcher executes any caller-supplied plugin.
//!
//! A modular contract accepts a plugin address from the caller and invokes it
//! with protocol context. Because the plugin address is never checked against
//! an approved list, a malicious plugin can perform unauthorized state changes.
//!
//! VULNERABILITY: `dispatch()` calls an arbitrary `plugin_id` supplied by the
//! caller without verifying it is governance-approved.
//!
//! SECURE MIRROR: `secure::SecureDispatcher` stores approved plugins through
//! governance and panics when an unapproved address is supplied.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    CallCount,
    LastPlugin,
}

#[contracttype]
pub enum PluginDataKey {
    ExecuteCount,
}

// ---------------------------------------------------------------------------
// Vulnerable dispatcher
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableDispatcher;

#[contractimpl]
impl VulnerableDispatcher {
    /// VULNERABLE: executes `plugin_id` without any allowlist check.
    ///
    /// # Vulnerability
    /// Caller supplies an arbitrary plugin address. A malicious plugin can
    /// perform unauthorized state changes or callbacks with no restriction.
    pub fn dispatch(env: Env, actor: Address, amount: i128, plugin_id: Address) {
        actor.require_auth();

        // ❌ No check that `plugin_id` is governance-approved.
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
            .get(&DataKey::CallCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::CallCount, &(count + 1));
        env.storage()
            .persistent()
            .set(&DataKey::LastPlugin, &plugin_id);
    }

    pub fn call_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::CallCount)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Malicious plugin
// ---------------------------------------------------------------------------

#[contract]
pub struct MaliciousPlugin;

#[contractimpl]
impl MaliciousPlugin {
    /// Records that it was executed. In a real attack this could drain
    /// balances, escalate privileges, or trigger unauthorized callbacks.
    pub fn execute(env: Env, _actor: Address, _amount: i128) {
        let count: u32 = env
            .storage()
            .persistent()
            .get(&PluginDataKey::ExecuteCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&PluginDataKey::ExecuteCount, &(count + 1));
    }

    pub fn execute_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&PluginDataKey::ExecuteCount)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        VulnerableDispatcherClient<'static>,
        Address,
        MaliciousPluginClient<'static>,
    ) {
        let env = Env::default();
        let dispatcher_id = env.register_contract(None, VulnerableDispatcher);
        let dispatcher = VulnerableDispatcherClient::new(&env, &dispatcher_id);
        let plugin_id = env.register_contract(None, MaliciousPlugin);
        let plugin = MaliciousPluginClient::new(&env, &plugin_id);
        (env, dispatcher, plugin_id, plugin)
    }

    /// Vulnerable path: dispatcher executes a malicious plugin without any check.
    #[test]
    fn test_vulnerable_executes_malicious_plugin() {
        let (env, dispatcher, plugin_id, plugin) = setup();
        env.mock_all_auths();

        let actor = Address::generate(&env);
        dispatcher.dispatch(&actor, &500, &plugin_id);

        // Both sides recorded the call — the malicious plugin ran unchecked.
        assert_eq!(dispatcher.call_count(), 1);
        assert_eq!(plugin.execute_count(), 1);
    }

    /// Boundary: the vulnerable dispatcher accepts *any* address, including a
    /// second rogue contract that was never registered as a plugin.
    #[test]
    fn test_vulnerable_accepts_any_address_as_plugin() {
        let (env, dispatcher, _plugin_id, _plugin) = setup();
        env.mock_all_auths();

        let actor = Address::generate(&env);
        let rogue_id = env.register_contract(None, MaliciousPlugin);

        dispatcher.dispatch(&actor, &100, &rogue_id);
        assert_eq!(dispatcher.call_count(), 1);
    }

    /// Secure path: governance-gated dispatcher rejects an unapproved plugin.
    #[test]
    #[should_panic]
    fn test_secure_rejects_unapproved_plugin() {
        use crate::secure::SecureDispatcherClient;

        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let dispatcher_id = env.register_contract(None, secure::SecureDispatcher);
        let dispatcher = SecureDispatcherClient::new(&env, &dispatcher_id);
        dispatcher.init(&admin);

        let plugin_id = env.register_contract(None, MaliciousPlugin);
        let actor = Address::generate(&env);

        // ✅ SECURE: plugin was never approved — must panic.
        dispatcher.dispatch(&actor, &500, &plugin_id);
    }

    /// Secure path: an approved plugin is accepted.
    #[test]
    fn test_secure_accepts_approved_plugin() {
        use crate::secure::SecureDispatcherClient;

        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let dispatcher_id = env.register_contract(None, secure::SecureDispatcher);
        let dispatcher = SecureDispatcherClient::new(&env, &dispatcher_id);
        dispatcher.init(&admin);

        let plugin_id = env.register_contract(None, MaliciousPlugin);
        dispatcher.approve_plugin(&admin, &plugin_id);

        let actor = Address::generate(&env);
        dispatcher.dispatch(&actor, &500, &plugin_id);

        assert_eq!(dispatcher.call_count(), 1);
    }
}
