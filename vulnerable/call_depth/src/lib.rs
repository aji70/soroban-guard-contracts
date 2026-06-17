//! VULNERABLE: No cross-contract call depth guard.
//!
//! Soroban enforces a maximum cross-contract call depth. A contract that
//! forwards a call down a chain of contracts without tracking depth will
//! panic at the host limit mid-execution, potentially leaving state
//! partially updated.
//!
//! Soroban prohibits a contract from re-entering itself, so the chain is
//! modelled as a list of distinct contract instances (deployed from the
//! same Wasm) that each forward to the next — the same shape a chain of
//! malicious or buggy forwarder/proxy contracts would take on-chain.
//!
//! VULNERABILITY: `process()` forwards to the next contract in `chain` with
//! no depth check. An attacker can craft a chain long enough to hit the
//! Soroban call depth limit at a critical point, causing a panic.
//!
//! SECURE MIRROR: `process_safe()` rejects chains longer than MAX_DEPTH
//! before any state mutation occurs.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

/// Safe recursion threshold — well below Soroban's host limit.
pub const MAX_DEPTH: u32 = 10;

#[contracttype]
pub enum DataKey {
    Processed,
    ProcessedCount,
}

#[contract]
pub struct CallDepthContract;

#[contractimpl]
impl CallDepthContract {
    /// VULNERABLE: forwards to the next contract in `chain` with no depth
    /// guard. Will panic at the Soroban call depth limit mid-chain; any
    /// state updates below the forwarded call may never be reached.
    ///
    /// # Vulnerability
    /// No depth check before forwarding. Impact: panic mid-execution leaves state partially updated.
    pub fn process(env: Env, chain: Vec<Address>) {
        // ❌ No depth check — a long enough chain hits Soroban's call depth limit and panics
        if let Some(next_id) = chain.first() {
            CallDepthContractClient::new(&env, &next_id).process(&chain.slice(1..));
        }
        // State update here may never be reached if depth limit is hit above
        env.storage().persistent().set(&DataKey::Processed, &true);
        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProcessedCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::ProcessedCount, &(count + 1));
    }

    /// SECURE: rejects chains longer than MAX_DEPTH before any forwarded
    /// call or state mutation.
    pub fn process_safe(env: Env, chain: Vec<Address>) {
        // ✅ Explicit depth guard — panics with a clear message before forwarding
        assert!(
            chain.len() <= MAX_DEPTH,
            "call depth exceeds safe threshold"
        );
        if let Some(next_id) = chain.first() {
            CallDepthContractClient::new(&env, &next_id).process_safe(&chain.slice(1..));
        }
        env.storage().persistent().set(&DataKey::Processed, &true);
        let count: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ProcessedCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::ProcessedCount, &(count + 1));
    }

    /// Returns `true` if the contract has been processed at least once.
    pub fn is_processed(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Processed)
            .unwrap_or(false)
    }

    /// Returns the total number of times `process` or `process_safe` has completed.
    pub fn processed_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ProcessedCount)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    /// Deploys a fresh `CallDepthContract` entry point plus `hops` additional
    /// distinct instances to forward through. Soroban prohibits a contract
    /// from re-entering itself, so each hop in the chain must be a separate
    /// deployed instance.
    fn build_chain(env: &Env, hops: u32) -> (Address, Vec<Address>) {
        let entry = env.register_contract(None, CallDepthContract);
        let mut chain = Vec::new(env);
        for _ in 0..hops {
            chain.push_back(env.register_contract(None, CallDepthContract));
        }
        (entry, chain)
    }

    #[test]
    fn test_shallow_recursion_completes() {
        let env = Env::default();
        let (entry, chain) = build_chain(&env, 0);
        let client = CallDepthContractClient::new(&env, &entry);

        // Empty chain — no forwarding, just sets state
        client.process(&chain);
        assert!(client.is_processed());
    }

    #[test]
    #[should_panic]
    fn test_deep_recursion_hits_call_depth_limit() {
        let env = Env::default();
        // Long chain — will exceed Soroban's cross-contract call depth limit (100)
        let (entry, chain) = build_chain(&env, 150);
        let client = CallDepthContractClient::new(&env, &entry);

        client.process(&chain);
    }

    #[test]
    fn test_secure_shallow_recursion_completes() {
        let env = Env::default();
        let (entry, chain) = build_chain(&env, 5);
        let client = CallDepthContractClient::new(&env, &entry);

        client.process_safe(&chain);
        assert!(client.is_processed());
    }

    #[test]
    #[should_panic(expected = "call depth exceeds safe threshold")]
    fn test_secure_rejects_depth_above_max() {
        let env = Env::default();
        let (entry, chain) = build_chain(&env, MAX_DEPTH + 1);
        let client = CallDepthContractClient::new(&env, &entry);

        client.process_safe(&chain);
    }
}
