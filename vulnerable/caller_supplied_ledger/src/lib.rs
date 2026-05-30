//! VULNERABLE: Caller-Supplied Ledger Context
//!
//! A time-sensitive vesting/lock contract that accepts a `current_ledger` argument
//! from the caller instead of reading the ledger sequence from `env.ledger()`.
//! Attackers can bypass lock periods, expiry checks, and vesting schedules by
//! supplying an arbitrarily large ledger sequence.
//!
//! VULNERABILITY: The contract trusts caller-supplied ledger values for time-
//! sensitive checks (lock expiry, vesting cliff, deadline enforcement).
//! An attacker can call `withdraw` with a fabricated `current_ledger` that
//! satisfies all time checks, draining funds before the intended unlock.
//!
//! Severity: Critical
//!
//! SECURE MIRROR: `secure::SecureVestingContract` reads `env.ledger().sequence()`
//! directly and ignores any caller-supplied ledger value.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Total amount deposited by a user.
    Balance(Address),
    /// Ledger sequence at which the deposit was made.
    DepositLedger(Address),
    /// Lock duration in ledger sequence steps.
    LockDuration(Address),
    /// Cliff duration in ledger sequence steps (funds cannot be withdrawn before cliff).
    CliffDuration(Address),
    /// Total amount that has been vested/released so far.
    Released(Address),
}

// ── Vulnerable contract ──────────────────────────────────────────────────────

#[contract]
pub struct CallerSuppliedLedgerContract;

#[contractimpl]
impl CallerSuppliedLedgerContract {
    /// Deposit `amount` with a lock period of `lock_duration` ledger steps and
    /// an optional cliff of `cliff_duration` ledger steps.
    ///
    /// The deposit ledger is read from `env.ledger().sequence()` — this part is
    /// correct. The vulnerability is in the withdraw path.
    pub fn deposit(
        env: Env,
        user: Address,
        amount: i128,
        lock_duration: u32,
        cliff_duration: u32,
    ) {
        user.require_auth();

        let balance_key = DataKey::Balance(user.clone());
        let current_balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        // Store the deposit ledger (correctly read from env)
        env.storage()
            .persistent()
            .set(&DataKey::DepositLedger(user.clone()), &env.ledger().sequence());

        env.storage()
            .persistent()
            .set(&DataKey::LockDuration(user.clone()), &lock_duration);

        env.storage()
            .persistent()
            .set(&DataKey::CliffDuration(user.clone()), &cliff_duration);

        // Initialize released amount
        env.storage()
            .persistent()
            .set(&DataKey::Released(user), &0i128);
    }

    /// ❌ VULNERABLE: Accepts `current_ledger` from the caller instead of reading
    /// from `env.ledger().sequence()`. An attacker can supply a ledger far in the
    /// future to bypass all time locks and withdraw funds immediately.
    ///
    /// # Arguments
    /// * `user` - The address to withdraw for.
    /// * `amount` - The amount to withdraw.
    /// * `current_ledger` - **Caller-supplied** ledger sequence — THE BUG.
    ///   The contract trusts this value for all time-sensitive checks.
    pub fn withdraw(env: Env, user: Address, amount: i128, current_ledger: u32) {
        user.require_auth();

        let balance_key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&balance_key).expect("no balance");

        let deposit_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::DepositLedger(user.clone()))
            .expect("no deposit");

        let lock_duration: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LockDuration(user.clone()))
            .expect("no lock duration");

        let cliff_duration: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::CliffDuration(user.clone()))
            .expect("no cliff duration");

        let released: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Released(user.clone()))
            .unwrap_or(0);

        // ❌ BUG: Uses caller-supplied `current_ledger` instead of `env.ledger().sequence()`.
        // An attacker can set `current_ledger` to any value to bypass these checks.

        // Cliff check: cannot withdraw before cliff period ends
        if current_ledger < deposit_ledger + cliff_duration {
            panic!("still in cliff period");
        }

        // Lock check: cannot withdraw more than vested amount
        let elapsed = current_ledger - deposit_ledger;
        let vested_amount = if elapsed >= lock_duration {
            balance
        } else {
            // Linear vesting: (elapsed / lock_duration) * balance
            (i128::from(elapsed) * balance) / i128::from(lock_duration)
        };

        let withdrawable = vested_amount - released;
        if amount > withdrawable {
            panic!("insufficient vested amount");
        }

        // Update released amount
        env.storage()
            .persistent()
            .set(&DataKey::Released(user.clone()), &(released + amount));

        // Update balance
        env.storage()
            .persistent()
            .set(&balance_key, &(balance - amount));
    }

    /// Returns the current balance of `user`.
    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    /// Returns the total amount released so far for `user`.
    pub fn released(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Released(user))
            .unwrap_or(0)
    }

    /// Returns the deposit ledger sequence for `user`.
    pub fn deposit_ledger(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::DepositLedger(user))
    }

    /// Returns the lock duration for `user`.
    pub fn lock_duration(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::LockDuration(user))
    }

    /// Returns the cliff duration for `user`.
    pub fn cliff_duration(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::CliffDuration(user))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, CallerSuppliedLedgerContract);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        (env, id, alice, bob)
    }

    /// Normal deposit works correctly.
    #[test]
    fn test_deposit() {
        let (env, id, alice, _bob) = setup();
        let client = CallerSuppliedLedgerContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        client.deposit(&alice, &1000, &100, &50);

        assert_eq!(client.balance(&alice), 1000);
        assert_eq!(client.deposit_ledger(&alice), Some(100));
        assert_eq!(client.lock_duration(&alice), Some(100));
        assert_eq!(client.cliff_duration(&alice), Some(50));
    }

    /// Withdrawal during cliff period should fail (when using real ledger).
    #[test]
    #[should_panic(expected = "still in cliff period")]
    fn test_withdraw_during_cliff_fails_with_real_ledger() {
        let (env, id, alice, _bob) = setup();
        let client = CallerSuppliedLedgerContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        client.deposit(&alice, &1000, &100, &50);

        // Real ledger is 105, still in cliff (cliff ends at 150)
        env.ledger().set_sequence_number(105);

        // ❌ Attacker supplies current_ledger=105 (matches real ledger) — this should fail
        client.withdraw(&alice, &100, &105);
    }

    /// ❌ DEMONSTRATES VULNERABILITY: Attacker bypasses cliff by supplying a
    /// fabricated `current_ledger` that is past the cliff period.
    #[test]
    fn test_vulnerability_bypass_cliff_with_fabricated_ledger() {
        let (env, id, alice, _bob) = setup();
        let client = CallerSuppliedLedgerContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        client.deposit(&alice, &1000, &100, &50);

        // Real ledger is still 105 (still in cliff), but attacker supplies
        // current_ledger=200 which is past the cliff (150) AND past the lock (200).
        env.ledger().set_sequence_number(105);

        // ❌ VULNERABLE: withdrawal succeeds because the contract trusts the
        // caller-supplied `current_ledger` instead of reading from env.
        client.withdraw(&alice, &1000, &200);

        assert_eq!(
            client.balance(&alice),
            0,
            "attacker drained all funds by fabricating ledger sequence"
        );
    }

    /// ❌ DEMONSTRATES VULNERABILITY: Attacker bypasses linear vesting schedule
    /// by supplying a ledger far in the future.
    #[test]
    fn test_vulnerability_bypass_vesting_with_fabricated_ledger() {
        let (env, id, alice, _bob) = setup();
        let client = CallerSuppliedLedgerContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        // Lock for 1000 ledgers, cliff for 100 ledgers
        client.deposit(&alice, &5000, &1000, &100);

        // Real ledger is 150 — only 50 ledgers have passed, so only 5% vested
        // (50/1000 * 5000 = 250). But attacker supplies current_ledger=1100
        // which is past the full lock period.
        env.ledger().set_sequence_number(150);

        // ❌ VULNERABLE: withdraws full amount by fabricating ledger
        client.withdraw(&alice, &5000, &1100);

        assert_eq!(
            client.balance(&alice),
            0,
            "attacker withdrew full vesting amount by fabricating ledger"
        );
    }

    /// ❌ DEMONSTRATES VULNERABILITY: Attacker can withdraw more than the
    /// linearly vested amount by supplying a partially-advanced fabricated ledger.
    #[test]
    fn test_vulnerability_partial_vesting_bypass() {
        let (env, id, alice, _bob) = setup();
        let client = CallerSuppliedLedgerContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        // Lock for 1000 ledgers, no cliff
        client.deposit(&alice, &10000, &1000, &0);

        // Real ledger is 200 — only 10% vested (1000). But attacker supplies
        // current_ledger=600 which implies 50% vested (5000).
        env.ledger().set_sequence_number(200);

        // ❌ VULNERABLE: withdraws 5000 when only 1000 should be vested
        client.withdraw(&alice, &5000, &600);

        assert_eq!(
            client.released(&alice),
            5000,
            "attacker withdrew more than vested amount"
        );
    }

    /// Normal withdrawal works correctly when caller supplies the real ledger.
    #[test]
    fn test_withdraw_after_lock_with_real_ledger() {
        let (env, id, alice, _bob) = setup();
        let client = CallerSuppliedLedgerContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        client.deposit(&alice, &1000, &100, &50);

        // Advance past lock period
        env.ledger().set_sequence_number(250);

        // Supply the real ledger value — should succeed
        client.withdraw(&alice, &1000, &250);

        assert_eq!(client.balance(&alice), 0);
    }

    /// Secure version: rejects fabricated ledger values.
    #[test]
    #[should_panic(expected = "still in cliff period")]
    fn test_secure_rejects_fabricated_ledger() {
        use crate::secure::SecureVestingContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVestingContract);
        let alice = Address::generate(&env);
        let client = SecureVestingContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        client.deposit(&alice, &1000, &100, &50);

        // Real ledger is 105 (still in cliff), but attacker tries to supply
        // a fabricated ledger. The secure version ignores the caller-supplied
        // value and reads from env.ledger().sequence() instead.
        env.ledger().set_sequence_number(105);

        // The secure version's withdraw only takes (user, amount) — no ledger param.
        // This call would fail because the real ledger is still in cliff.
        client.withdraw(&alice, &100);
    }

    /// Secure version: normal withdrawal works.
    #[test]
    fn test_secure_normal_withdrawal() {
        use crate::secure::SecureVestingContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVestingContract);
        let alice = Address::generate(&env);
        let client = SecureVestingContractClient::new(&env, &id);

        env.ledger().set_sequence_number(100);
        client.deposit(&alice, &1000, &100, &50);

        // Advance past lock
        env.ledger().set_sequence_number(250);

        // Secure version succeeds with real ledger
        client.withdraw(&alice, &1000);

        assert_eq!(client.balance(&alice), 0);
    }
}
