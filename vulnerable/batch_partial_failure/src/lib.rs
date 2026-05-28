//! VULNERABLE: Batch partial failure — executor continues after an inner
//! operation fails and records the whole batch as successful.
//!
//! A batch of transfers is processed in a loop. When one transfer fails
//! (e.g. insufficient balance), the error is silently swallowed, subsequent
//! operations mutate state, and the batch is marked complete. Callers and
//! integrations observe a "success" flag while the ledger is in a partially
//! applied state.
//!
//! VULNERABILITY: `execute_batch()` catches per-operation failures and
//! continues, leaving state partially updated and reporting overall success.
//!
//! SECURE MIRROR: `secure::SecureBatchExecutor` uses atomic semantics —
//! it panics on the first failure, reverting all state changes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    Balance(Address),
    /// Number of operations that succeeded in the last batch.
    SuccessCount,
    /// Whether the last batch was recorded as complete.
    BatchComplete,
}

// ---------------------------------------------------------------------------
// Transfer operation (plain struct passed in the batch)
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct Transfer {
    pub from: Address,
    pub to: Address,
    pub amount: i128,
}

// ---------------------------------------------------------------------------
// Vulnerable batch executor
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableBatchExecutor;

#[contractimpl]
impl VulnerableBatchExecutor {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// VULNERABLE: continues after a failed inner transfer and marks the
    /// batch complete regardless of per-operation errors.
    ///
    /// # Vulnerability
    /// Partial state is committed. A failing middle operation is silently
    /// skipped; later operations still execute and the batch is flagged
    /// as complete, misleading callers about the true outcome.
    pub fn execute_batch(env: Env, ops: Vec<Transfer>) {
        let mut success_count: u32 = 0;

        for op in ops.iter() {
            let from_key = DataKey::Balance(op.from.clone());
            let from_bal: i128 = env
                .storage()
                .persistent()
                .get(&from_key)
                .unwrap_or(0);

            // ❌ Silently skip failures — subsequent ops still run.
            if from_bal < op.amount {
                continue;
            }

            env.storage()
                .persistent()
                .set(&from_key, &(from_bal - op.amount));

            let to_key = DataKey::Balance(op.to.clone());
            let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
            env.storage()
                .persistent()
                .set(&to_key, &(to_bal + op.amount));

            success_count += 1;
        }

        // ❌ Marks batch complete even when some operations were skipped.
        env.storage()
            .persistent()
            .set(&DataKey::SuccessCount, &success_count);
        env.storage()
            .persistent()
            .set(&DataKey::BatchComplete, &true);
    }

    pub fn balance(env: Env, who: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(who))
            .unwrap_or(0)
    }

    pub fn success_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::SuccessCount)
            .unwrap_or(0)
    }

    pub fn batch_complete(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::BatchComplete)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Address, Env};

    fn setup() -> (Env, VulnerableBatchExecutorClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableBatchExecutor);
        let client = VulnerableBatchExecutorClient::new(&env, &id);
        (env, client)
    }

    /// Vulnerable path: middle op fails (insufficient balance), final op still
    /// executes, and the batch is marked complete — partial state committed.
    #[test]
    fn test_vulnerable_partial_failure_marked_complete() {
        let (env, executor) = setup();
        env.mock_all_auths();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let carol = Address::generate(&env);

        executor.mint(&alice, &500);
        executor.mint(&carol, &200);

        // op[0]: alice → bob 300  (ok)
        // op[1]: bob   → carol 999 (fails — bob has 0 before op[0] settles... wait,
        //         bob receives in op[0] so has 300; 999 > 300 → fails)
        // op[2]: carol → alice 100 (ok — carol has 200)
        let ops = vec![
            &env,
            Transfer { from: alice.clone(), to: bob.clone(),   amount: 300 },
            Transfer { from: bob.clone(),   to: carol.clone(), amount: 999 },
            Transfer { from: carol.clone(), to: alice.clone(), amount: 100 },
        ];

        executor.execute_batch(&ops);

        // Batch is flagged complete despite op[1] failing.
        assert!(executor.batch_complete());
        // Only 2 of 3 ops succeeded.
        assert_eq!(executor.success_count(), 2);
        // State is partially applied: alice lost 300 but got 100 back.
        assert_eq!(executor.balance(&alice), 300);  // 500 - 300 + 100
        assert_eq!(executor.balance(&bob),   300);  // received 300, failed send
        assert_eq!(executor.balance(&carol), 100);  // 200 + 0 - 100
    }

    /// Boundary: a batch where every op fails still sets BatchComplete = true.
    #[test]
    fn test_vulnerable_all_fail_still_complete() {
        let (env, executor) = setup();
        env.mock_all_auths();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        let ops = vec![
            &env,
            Transfer { from: alice.clone(), to: bob.clone(), amount: 1000 },
        ];

        executor.execute_batch(&ops);

        assert!(executor.batch_complete());
        assert_eq!(executor.success_count(), 0);
        // No state changed, but batch is still "complete".
        assert_eq!(executor.balance(&alice), 0);
    }

    /// Secure path: atomic batch panics on the first failing op, reverting all.
    #[test]
    #[should_panic]
    fn test_secure_reverts_on_partial_failure() {
        use crate::secure::SecureBatchExecutorClient;

        let env = Env::default();
        env.mock_all_auths();

        let id = env.register_contract(None, secure::SecureBatchExecutor);
        let executor = SecureBatchExecutorClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let carol = Address::generate(&env);

        executor.mint(&alice, &500);
        executor.mint(&carol, &200);

        let ops = vec![
            &env,
            Transfer { from: alice.clone(), to: bob.clone(),   amount: 300 },
            Transfer { from: bob.clone(),   to: carol.clone(), amount: 999 }, // fails
            Transfer { from: carol.clone(), to: alice.clone(), amount: 100 },
        ];

        // ✅ SECURE: panics on op[1], entire batch reverts.
        executor.execute_batch(&ops);
    }

    /// Secure path: a fully valid batch completes and all balances are correct.
    #[test]
    fn test_secure_valid_batch_succeeds() {
        use crate::secure::SecureBatchExecutorClient;

        let env = Env::default();
        env.mock_all_auths();

        let id = env.register_contract(None, secure::SecureBatchExecutor);
        let executor = SecureBatchExecutorClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        executor.mint(&alice, &1000);

        let ops = vec![
            &env,
            Transfer { from: alice.clone(), to: bob.clone(), amount: 400 },
            Transfer { from: alice.clone(), to: bob.clone(), amount: 200 },
        ];

        executor.execute_batch(&ops);

        assert_eq!(executor.balance(&alice), 400);
        assert_eq!(executor.balance(&bob),   600);
    }
}
