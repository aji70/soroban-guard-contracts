//! VULNERABLE: Admin Timelock Rewrite Attack
//!
//! A timelock contract that stores only one pending action per target without
//! binding the queue key to the payload hash. An admin can queue a harmless
//! action, wait through the delay, then overwrite the payload with a dangerous
//! action while keeping the old execution timestamp.
//!
//! VULNERABILITY: Queue key omits payload hash and nonce, allowing payload
//! substitution without resetting the delay timer.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    QueuedAction(Address), // ❌ BUG: Key only includes target, not payload hash
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuedAction {
    pub target: Address,
    pub function_name: soroban_sdk::String,
    pub args: Bytes,
    pub queued_at: u64,
    pub delay: u64,
}

#[contract]
pub struct TimelockContract;

#[contractimpl]
impl TimelockContract {
    pub fn initialize(env: Env, admin: Address, default_delay: u64) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&soroban_sdk::symbol_short!("delay"), &default_delay);
    }

    /// VULNERABLE: Queue action using only target as key, ignoring payload
    pub fn queue_action(
        env: Env,
        target: Address,
        function_name: soroban_sdk::String,
        args: Bytes,
    ) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let delay: u64 = env.storage().persistent().get(&soroban_sdk::symbol_short!("delay")).unwrap_or(86400);
        let current_ledger = env.ledger().sequence();

        let action = QueuedAction {
            target: target.clone(),
            function_name,
            args,
            queued_at: current_ledger,
            delay,
        };

        // ❌ BUG: Key only includes target, allows overwriting with different payload
        env.storage().persistent().set(&DataKey::QueuedAction(target), &action);
    }

    /// VULNERABLE: Execute without verifying payload hasn't changed
    pub fn execute_action(env: Env, target: Address) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let action: QueuedAction = env
            .storage()
            .persistent()
            .get(&DataKey::QueuedAction(target.clone()))
            .expect("no queued action");

        let current_ledger = env.ledger().sequence();
        
        // ❌ BUG: Only checks time delay, not if payload was modified
        if current_ledger < action.queued_at + action.delay {
            panic!("timelock not expired");
        }

        // Execute the action (simplified - in real contract would invoke target)
        env.storage().persistent().remove(&DataKey::QueuedAction(target));
        
        env.events().publish(
            (soroban_sdk::symbol_short!("executed"),),
            (action.target, action.function_name, action.args),
        );
    }

    pub fn get_queued_action(env: Env, target: Address) -> Option<QueuedAction> {
        env.storage().persistent().get(&DataKey::QueuedAction(target))
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env, String};

    #[test]
    fn test_queue_and_execute_after_delay() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimelockContract);
        let client = TimelockContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let target = Address::generate(&env);
        
        client.initialize(&admin, &100);
        
        env.mock_all_auths();
        let func_name = String::from_str(&env, "transfer");
        let args = Bytes::from_array(&env, &[1, 2, 3]);
        
        client.queue_action(&target, &func_name, &args);
        
        // Advance ledgers past delay
        env.ledger().with_mut(|li| li.sequence_number += 101);
        
        client.execute_action(&target);
    }

    /// Demonstrates the vulnerability: payload can be rewritten without resetting delay
    #[test]
    fn test_payload_rewrite_attack() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimelockContract);
        let client = TimelockContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let target = Address::generate(&env);
        
        client.initialize(&admin, &100);
        env.mock_all_auths();

        // 1. Queue harmless action
        let harmless_func = String::from_str(&env, "view_balance");
        let harmless_args = Bytes::from_array(&env, &[0]);
        client.queue_action(&target, &harmless_func, &harmless_args);

        // 2. Wait through delay
        env.ledger().with_mut(|li| li.sequence_number += 101);

        // 3. ❌ ATTACK: Overwrite with dangerous payload using same key
        let dangerous_func = String::from_str(&env, "drain_all");
        let dangerous_args = Bytes::from_array(&env, &[255, 255, 255]);
        client.queue_action(&target, &dangerous_func, &dangerous_args);

        // 4. Execute immediately - should fail but doesn't in vulnerable version
        client.execute_action(&target);

        // Verify the dangerous action was executed
        let events = env.events().all();
        let last_event = events.last().unwrap();
        assert_eq!(last_event.2.get(1).unwrap(), dangerous_func);
    }

    #[test]
    #[should_panic(expected = "timelock not expired")]
    fn test_cannot_execute_before_delay() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimelockContract);
        let client = TimelockContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let target = Address::generate(&env);
        
        client.initialize(&admin, &100);
        env.mock_all_auths();

        let func_name = String::from_str(&env, "transfer");
        let args = Bytes::from_array(&env, &[1, 2, 3]);
        client.queue_action(&target, &func_name, &args);

        // Try to execute immediately - should fail
        client.execute_action(&target);
    }
}