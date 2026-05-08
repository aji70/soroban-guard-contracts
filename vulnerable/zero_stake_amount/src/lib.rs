//! VULNERABLE: Stake Function Does Not Validate Amount > 0
//!
//! A staking contract where `stake()` accepts any i128 value including zero
//! and negative numbers. A zero-amount stake creates a storage entry and
//! emits an event without transferring any tokens, polluting ledger state and
//! wasting resources. Negative amounts silently underflow the staker's
//! recorded balance.
//!
//! VULNERABILITY: `stake()` never checks `amount > 0` before updating
//! persistent storage, so callers can corrupt the ledger for free.
//!
//! SECURE MIRROR: `secure::SecureStaking` adds
//! `if amount <= 0 { panic!("amount must be positive") }` at the top of
//! `stake`, rejecting both zero and negative inputs.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Stake(Address),
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct VulnerableStaking;

#[contractimpl]
impl VulnerableStaking {
    /// VULNERABLE: amount is never validated — zero and negative values are
    /// accepted, polluting storage and potentially underflowing balances.
    ///
    /// # Vulnerability
    /// Missing `amount > 0` guard. Impact: free storage pollution and balance
    /// underflow via negative stake amounts.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ❌ Missing: if amount <= 0 { panic!("amount must be positive") }
        let key = DataKey::Stake(staker.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Returns the staked balance for `staker`.
    pub fn balance(env: Env, staker: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableStakingClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableStaking);
        let client = VulnerableStakingClient::new(&env, &id);
        let staker = Address::generate(&env);
        (env, client, staker)
    }

    /// Demonstrates the bug: staking zero succeeds and creates a storage entry.
    /// A correct implementation should panic here.
    #[test]
    fn test_stake_zero_amount_succeeds() {
        let (_env, client, staker) = setup();
        // Should panic in a fixed contract, but the vulnerable one allows it.
        client.stake(&staker, &0);
        // Storage entry was created with a zero balance — wasted ledger space.
        assert_eq!(client.balance(&staker), 0);
    }

    /// Demonstrates the bug: staking a negative amount does not revert and
    /// silently underflows the staker's recorded balance.
    #[test]
    fn test_stake_negative_amount_does_not_revert() {
        let (_env, client, staker) = setup();
        client.stake(&staker, &1000);
        // Negative stake silently reduces the balance — this is the bug.
        client.stake(&staker, &-500);
        assert_eq!(client.balance(&staker), 500);
    }
}
