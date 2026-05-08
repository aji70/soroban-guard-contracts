//! VULNERABLE: Timestamp-based Time Locks
//!
//! A time-locked vault that uses `env.ledger().timestamp()` to enforce lock periods.
//! This is vulnerable to timestamp manipulation within the validator drift window.
//!
//! VULNERABILITY: Using timestamps instead of ledger sequences for time-locking.
//! Validators can manipulate timestamps within a drift window (typically 5-15 seconds),
//! allowing premature withdrawal of locked funds.
//!
//! ATTACK VECTOR: Timestamp Drift
//! - Validators have a "drift window" where they can adjust timestamps
//! - An attacker can time their transaction to land in a block with manipulated timestamp
//! - This allows withdrawing funds before the intended lock period expires
//! - Unlike ledger sequences, timestamps are not monotonically increasing per ledger

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
    UnlockTime(Address),
}

#[contract]
pub struct TimeLockedVault;

#[contractimpl]
impl TimeLockedVault {
    /// Deposit `amount` and set an unlock timestamp (seconds since Unix epoch).
    /// Requires user auth.
    pub fn deposit(env: Env, user: Address, amount: i128, unlock_timestamp: u64) {
        user.require_auth();

        // Store the balance
        let balance_key = DataKey::Balance(user.clone());
        let current_balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        // Set the unlock time
        let unlock_key = DataKey::UnlockTime(user);
        env.storage()
            .persistent()
            .set(&unlock_key, &unlock_timestamp);
    }

    /// Withdraw funds after the lock period expires.
    /// VULNERABLE: Uses timestamp which can be manipulated by validators.
    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();

        let unlock_key = DataKey::UnlockTime(user.clone());
        let unlock_time: u64 = env.storage().persistent().get(&unlock_key).expect("unlock time not set");

        // ❌ VULNERABLE: Timestamp can be manipulated within validator drift window
        // Validators can adjust timestamps by several seconds, allowing premature withdrawal
        if env.ledger().timestamp() < unlock_time {
            panic!("still locked");
        }

        // Release all funds
        let balance_key = DataKey::Balance(user.clone());
        let _balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);

        // Reset balance and unlock time
        env.storage().persistent().set(&balance_key, &0i128);
        env.storage().persistent().remove(&unlock_key);
    }

    /// Returns the balance of `user`, defaulting to 0.
    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    /// Returns the unlock timestamp for `user`, or `None` if no lock exists.
    pub fn unlock_time(env: Env, user: Address) -> Option<u64> {
        env.storage().persistent().get(&DataKey::UnlockTime(user))
    }

    /// Returns the current ledger timestamp in seconds since Unix epoch.
    pub fn current_timestamp(env: Env) -> u64 {
        env.ledger().timestamp()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    #[test]
    fn test_deposit_and_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimeLockedVault);
        let client = TimeLockedVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let unlock_time = 1000000; // Some future timestamp

        env.mock_all_auths();
        client.deposit(&alice, &1000, &unlock_time);

        assert_eq!(client.balance(&alice), 1000);
        assert_eq!(client.unlock_time(&alice), Some(unlock_time));
    }

    /// Withdrawal after lock period succeeds.
    #[test]
    fn test_withdrawal_after_lock_succeeds() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimeLockedVault);
        let client = TimeLockedVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let unlock_time = 1000000; // Some future timestamp

        env.mock_all_auths();
        client.deposit(&alice, &1000, &unlock_time);

        // Advance ledger timestamp past unlock time
        env.ledger().set_timestamp(unlock_time + 1);

        // Should succeed
        client.withdraw(&alice);

        assert_eq!(client.balance(&alice), 0);
        assert_eq!(client.unlock_time(&alice), None);
    }

    /// Withdrawal before lock period fails.
    #[test]
    #[should_panic(expected = "still locked")]
    fn test_withdrawal_before_lock_fails() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimeLockedVault);
        let client = TimeLockedVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let unlock_time = 1000000; // Some future timestamp

        env.mock_all_auths();
        client.deposit(&alice, &1000, &unlock_time);

        // Set timestamp before unlock time
        env.ledger().set_timestamp(unlock_time - 1);

        // Should panic
        client.withdraw(&alice);
    }

    /// Demonstrates timestamp drift vulnerability.
    /// A validator can manipulate the timestamp to be at or past the unlock time
    /// slightly earlier than the real wall-clock time, enabling premature withdrawal.
    #[test]
    fn test_timestamp_drift_attack() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TimeLockedVault);
        let client = TimeLockedVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let unlock_time = 1000000u64;

        env.mock_all_auths();
        client.deposit(&alice, &1000, &unlock_time);

        // ATTACK: Validator sets the block timestamp to exactly unlock_time,
        // which is within the drift window (typically ±15 s of real time).
        // The contract accepts it because timestamp >= unlock_time.
        env.ledger().set_timestamp(unlock_time);

        // ❌ VULNERABLE: withdrawal succeeds even though real wall-clock time
        // may still be before the intended lock expiry.
        client.withdraw(&alice);

        assert_eq!(client.balance(&alice), 0);
    }
}
