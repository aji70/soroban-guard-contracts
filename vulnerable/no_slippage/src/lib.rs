//! VULNERABLE: No Slippage Protection in Token Swap
//!
//! An AMM-style swap contract that accepts no `min_amount_out` parameter.
//! An attacker can sandwich the victim's transaction: front-run to move the
//! pool price unfavourably, let the victim's swap execute at the worse rate,
//! then back-run to pocket the difference — leaving the victim with far fewer
//! tokens than expected.
//!
//! VULNERABILITY: `swap()` calculates output via the constant-product formula
//! but never asserts `amount_out >= min_amount_out`, so any price impact is
//! silently accepted.
//!
//! SECURE MIRROR: `secure::SecureAmm` requires a `min_amount_out` argument and
//! panics with `"slippage exceeded"` when the output falls below the threshold.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Reserve of token A in the pool.
    ReserveA,
    /// Reserve of token B in the pool.
    ReserveB,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Constant-product AMM output: amount_out = (amount_in * reserve_out) / (reserve_in + amount_in)
pub(crate) fn calculate_out(env: &Env, amount_in: i128) -> i128 {
    let reserve_in: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::ReserveA)
        .unwrap_or(0);
    let reserve_out: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::ReserveB)
        .unwrap_or(0);
    assert!(reserve_in > 0 && reserve_out > 0, "pool not initialised");
    (amount_in * reserve_out) / (reserve_in + amount_in)
}

pub(crate) fn apply_swap(env: &Env, amount_in: i128, amount_out: i128) {
    let reserve_in: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::ReserveA)
        .expect("reserve A not initialized");
    let reserve_out: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::ReserveB)
        .expect("reserve B not initialized");
    env.storage()
        .persistent()
        .set(&DataKey::ReserveA, &(reserve_in + amount_in));
    env.storage()
        .persistent()
        .set(&DataKey::ReserveB, &(reserve_out - amount_out));
}

// ── Vulnerable AMM ────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableAmm;

#[contractimpl]
impl VulnerableAmm {
    /// Seed the pool with initial reserves for token A and token B.
    pub fn init(env: Env, reserve_a: i128, reserve_b: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::ReserveA, &reserve_a);
        env.storage()
            .persistent()
            .set(&DataKey::ReserveB, &reserve_b);
    }

    /// Swap `amount_in` of token A for token B.
    ///
    /// ❌ No `min_amount_out` check — any price impact is silently accepted.
    /// A sandwich attacker can manipulate the pool before this call and drain
    /// value from the user without any on-chain protection.
    pub fn swap(env: Env, user: Address, amount_in: i128) -> i128 {
        user.require_auth();
        let amount_out = calculate_out(&env, amount_in);
        apply_swap(&env, amount_in, amount_out);
        // ❌ Missing: assert!(amount_out >= min_amount_out, "slippage exceeded");
        amount_out
    }

    /// Returns the current reserve of token A.
    pub fn reserve_a(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::ReserveA)
            .unwrap_or(0)
    }

    /// Returns the current reserve of token B.
    pub fn reserve_b(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::ReserveB)
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Pool: 1000 A / 1000 B. Swap 100 A → expect ~90 B (constant product).
    fn setup_balanced() -> (Env, VulnerableAmmClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAmm);
        let client = VulnerableAmmClient::new(&env, &id);
        client.init(&1000, &1000);
        let user = Address::generate(&env);
        (env, client, user)
    }

    /// Normal swap on a balanced pool returns the expected amount.
    #[test]
    fn test_normal_swap_returns_expected_amount() {
        let (_env, client, user) = setup_balanced();
        // 100 * 1000 / (1000 + 100) = 90 (integer division)
        let out = client.swap(&user, &100);
        assert_eq!(out, 90);
    }

    /// Attacker front-runs by dumping a large amount into the pool, skewing the
    /// price. The victim's swap then executes at the manipulated rate and
    /// receives far fewer tokens — the vulnerable contract accepts this silently.
    #[test]
    fn test_manipulated_pool_returns_much_less_no_protection() {
        let (env, client, user) = setup_balanced();
        let attacker = Address::generate(&env);

        // Attacker front-runs: dumps 9000 A into the pool (pool: 10000 A / ~91 B).
        client.swap(&attacker, &9000);

        // Victim swaps 100 A at the now-skewed price.
        let victim_out = client.swap(&user, &100);

        // Without manipulation: ~90 B. After manipulation: ~0 B.
        // The vulnerable contract accepts this without complaint.
        assert!(
            victim_out < 5,
            "victim received {} B — far below fair value, but no protection triggered",
            victim_out
        );
    }
}
