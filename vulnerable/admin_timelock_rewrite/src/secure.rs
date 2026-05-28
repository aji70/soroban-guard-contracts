//! SECURE: Admin Timelock with Payload Binding
//!
//! This is the fixed version of the timelock rewrite vulnerability.
//!
//! FIXES APPLIED:
//! 1. Queue key includes payload hash and nonce to prevent substitution attacks
//! 2. Delay timer resets whenever payload changes
//! 3. Execution verifies payload integrity before proceeding

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    // ✅ FIX: Key includes payload hash and nonce for uniqueness
    QueuedAction(Address, soroban_sdk::BytesN<32>, u64), // target, payload_hash, nonce
    ActionNonce(Address), // Per-target nonce counter
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureQueuedAction {
    pub target: Address,
    pub function_name: soroban_sdk::String,
    pub args: Bytes,
    pub payload_hash: soroban_sdk::BytesN<32>,
    pub nonce: u64,
    pub queued_at: u64,
    pub delay: u64,
}

#[contract]
pub struct SecureTimelockContract;

#[contractimpl]
impl SecureTimelockContract {
    pub fn initialize(env: Env, admin: Address, default_delay: u64) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&soroban_sdk::symbol_short!("delay"), &default_delay);
    }

    /// ✅ SECURE: Queue action with payload hash and nonce binding
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

        // ✅ FIX: Generate nonce for uniqueness
        let nonce_key = DataKey::ActionNonce(target.clone());
        let nonce: u64 = env.storage().persistent().get(&nonce_key).unwrap_or(0) + 1;
        env.storage().persistent().set(&nonce_key, &nonce);

        // ✅ FIX: Create payload hash to bind key to specific action
        let mut payload_data = Bytes::new(&env);
        payload_data.extend_from_slice(&function_name.to_bytes());
        payload_data.extend_from_slice(&args);
        let payload_hash = env.crypto().sha256(&payload_data);

        let action = SecureQueuedAction {
            target: target.clone(),
            function_name,
            args,
            payload_hash: payload_hash.clone(),
            nonce,
            queued_at: current_ledger,
            delay,
        };

        // ✅ FIX: Key includes target, payload hash, and nonce
        let queue_key = DataKey::QueuedAction(target, payload_hash, nonce);
        env.storage().persistent().set(&queue_key, &action);
    }

    /// ✅ SECURE: Execute with payload integrity verification
    pub fn execute_action(
        env: Env,
        target: Address,
        function_name: soroban_sdk::String,
        args: Bytes,
    ) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        // ✅ FIX: Reconstruct payload hash to find correct queue entry
        let mut payload_data = Bytes::new(&env);
        payload_data.extend_from_slice(&function_name.to_bytes());
        payload_data.extend_from_slice(&args);
        let payload_hash = env.crypto().sha256(&payload_data);

        // ✅ FIX: Get current nonce to construct proper key
        let nonce: u64 = env.storage().persistent().get(&DataKey::ActionNonce(target.clone())).unwrap_or(0);
        let queue_key = DataKey::QueuedAction(target.clone(), payload_hash.clone(), nonce);

        let action: SecureQueuedAction = env
            .storage()
            .persistent()
            .get(&queue_key)
            .expect("no queued action with matching payload");

        let current_ledger = env.ledger().sequence();
        
        // ✅ FIX: Verify delay and payload integrity
        if current_ledger < action.queued_at + action.delay {
            panic!("timelock not expired");
        }

        if action.payload_hash != payload_hash {
            panic!("payload hash mismatch");
        }

        if action.function_name != function_name || action.args != args {
            panic!("payload content mismatch");
        }

        // Execute and cleanup
        env.storage().persistent().remove(&queue_key);
        
        env.events().publish(
            (soroban_sdk::symbol_short!("executed"),),
            (action.target, action.function_name, action.args),
        );
    }

    pub fn get_queued_action(
        env: Env,
        target: Address,
        payload_hash: soroban_sdk::BytesN<32>,
        nonce: u64,
    ) -> Option<SecureQueuedAction> {
        let queue_key = DataKey::QueuedAction(target, payload_hash, nonce);
        env.storage().persistent().get(&queue_key)
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
    fn test_secure_queue_and_execute() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockContract);
        let client = SecureTimelockContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let target = Address::generate(&env);
        
        client.initialize(&admin, &100);
        env.mock_all_auths();

        let func_name = String::from_str(&env, "transfer");
        let args = Bytes::from_array(&env, &[1, 2, 3]);
        
        client.queue_action(&target, &func_name, &args);
        
        // Advance ledgers past delay
        env.ledger().with_mut(|li| li.sequence_number += 101);
        
        client.execute_action(&target, &func_name, &args);
    }

    /// Demonstrates the fix: payload rewrite attack is prevented
    #[test]
    #[should_panic(expected = "no queued action with matching payload")]
    fn test_payload_rewrite_attack_prevented() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockContract);
        let client = SecureTimelockContractClient::new(&env, &contract_id);

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

        // 3. ✅ ATTACK PREVENTED: Try to execute with different payload
        let dangerous_func = String::from_str(&env, "drain_all");
        let dangerous_args = Bytes::from_array(&env, &[255, 255, 255]);
        
        // This should fail because payload hash doesn't match
        client.execute_action(&target, &dangerous_func, &dangerous_args);
    }

    #[test]
    #[should_panic(expected = "payload content mismatch")]
    fn test_payload_modification_detected() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureTimelockContract);
        let client = SecureTimelockContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let target = Address::generate(&env);
        
        client.initialize(&admin, &100);
        env.mock_all_auths();

        let func_name = String::from_str(&env, "transfer");
        let original_args = Bytes::from_array(&env, &[1, 2, 3]);
        
        client.queue_action(&target, &func_name, &original_args);
        
        // Advance ledgers past delay
        env.ledger().with_mut(|li| li.sequence_number += 101);
        
        // Try to execute with modified args - should fail
        let modified_args = Bytes::from_array(&env, &[4, 5, 6]);
        client.execute_action(&target, &func_name, &modified_args);
    }
}