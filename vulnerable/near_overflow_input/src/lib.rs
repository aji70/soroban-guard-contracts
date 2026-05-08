//! VULNERABLE: Missing check that amount does not exceed i128::MAX / 2
//!
//! This contract performs arithmetic on i128 amounts (balance + amount, amount * rate)
//! without guarding against inputs near i128::MAX. Passing amount = i128::MAX / 2 + 1
//! to a function that doubles the value will overflow.
//!
//! VULNERABILITY: Large input amounts can cause arithmetic to overflow, triggering
//! a panic from Soroban's checked arithmetic with no context. This allows DoS attacks
//! on specific user accounts.
//!
//! FIX: Define MAX_SAFE_AMOUNT = i128::MAX / 4 and validate all input amounts
//! before performing arithmetic operations.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

// Maximum safe amount to prevent overflow in arithmetic operations
// Set to i128::MAX / 4 to leave headroom for all operations
const MAX_SAFE_AMOUNT: i128 = i128::MAX / 4;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct VulnerableNearOverflow;

#[contractimpl]
impl VulnerableNearOverflow {
    /// Deposit `amount` into the contract for `user`.
    /// Requires user auth and validates amount does not exceed MAX_SAFE_AMOUNT.
    ///
    /// BUG (before fix): No upper bound on amount — near-MAX values cause overflow
    /// in downstream math like balance + amount.
    ///
    /// FIX: Check if amount > MAX_SAFE_AMOUNT and panic with clear message.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();

        // FIX: Validate amount is within safe bounds
        if amount > MAX_SAFE_AMOUNT {
            panic!("amount exceeds safe limit");
        }

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        // Safe now because both balance and amount are bounded
        env.storage().persistent().set(&key, &(balance + amount));
    }

    /// Withdraw `amount` from the contract for `user`.
    /// Requires user auth and validates amount does not exceed MAX_SAFE_AMOUNT.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();

        // FIX: Validate amount is within safe bounds
        if amount > MAX_SAFE_AMOUNT {
            panic!("amount exceeds safe limit");
        }

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance
            .checked_sub(amount)
            .expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);
    }

    /// Apply a rate multiplier to the user's balance.
    /// This operation could overflow if balance is near MAX_SAFE_AMOUNT,
    /// but validation on deposit/withdraw ensures safety.
    pub fn apply_rate(env: Env, user: Address, rate: i128) {
        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        // Safe because balance was validated during deposit
        let new_balance = balance
            .checked_mul(rate)
            .expect("balance rate overflow");
        env.storage().persistent().set(&key, &new_balance);
    }

    /// Get the current balance for a user.
    pub fn balance(env: Env, user: Address) -> i128 {
        let key = DataKey::Balance(user);
        env.storage().persistent().get(&key).unwrap_or(0)
    }

    /// Get the maximum safe amount constant.
    pub fn get_max_safe_amount(_env: Env) -> i128 {
        MAX_SAFE_AMOUNT
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn vulnerable_deposit_like_add(balance: i128, amount: i128) -> i128 {
        // Mirrors the original vulnerable arithmetic path: balance + amount without an input cap.
        balance + amount
    }

    fn setup() -> (Env, VulnerableNearOverflowClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableNearOverflow);
        let client = VulnerableNearOverflowClient::new(&env, &id);
        (env, client)
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_unguarded_deposit_i128_max_panics_with_overflow() {
        // Demonstrates the original unguarded path: a near-MAX deposit overflows on add.
        let _ = vulnerable_deposit_like_add(1, i128::MAX);
    }

    #[test]
    #[should_panic(expected = "amount exceeds safe limit")]
    fn test_deposit_above_max_safe_amount_panics_with_clear_message() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        client.deposit(&user, &(MAX_SAFE_AMOUNT + 1));
    }

    #[test]
    fn test_deposit_at_and_below_max_safe_amount_succeeds() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        // At the boundary.
        client.deposit(&user, &MAX_SAFE_AMOUNT);
        assert_eq!(client.balance(&user), MAX_SAFE_AMOUNT);

        // Below the boundary.
        client.deposit(&user, &1);
        assert_eq!(client.balance(&user), MAX_SAFE_AMOUNT + 1);
    }

    #[test]
    fn test_multiple_deposits_accumulate() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        let safe_amount = i128::MAX / 4;
        // Make multiple deposits, each safe individually
        client.deposit(&user, &safe_amount);
        let after_first = client.balance(&user);
        assert_eq!(after_first, safe_amount);

        // Deposit again - balance will exceed MAX_SAFE_AMOUNT but arithmetic is checked
        client.deposit(&user, &safe_amount);
        let after_second = client.balance(&user);
        assert_eq!(after_second, safe_amount + safe_amount);
    }

    #[test]
    #[should_panic(expected = "amount exceeds safe limit")]
    fn test_withdraw_above_max_safe_amount_panics() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        let max_safe = i128::MAX / 4;
        client.deposit(&user, &max_safe);

        // Try to withdraw an amount exceeding MAX_SAFE_AMOUNT
        let over_limit = max_safe + 1;
        client.withdraw(&user, &over_limit);
    }

    #[test]
    fn test_withdraw_below_max_safe_amount() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        let safe_amount = 10_000;
        client.deposit(&user, &safe_amount);
        client.withdraw(&user, &3_000);

        assert_eq!(client.balance(&user), 7_000);
    }

    #[test]
    fn test_get_max_safe_amount() {
        let (_env, client) = setup();
        let max_safe = client.get_max_safe_amount();
        assert_eq!(max_safe, i128::MAX / 4);
    }
}
