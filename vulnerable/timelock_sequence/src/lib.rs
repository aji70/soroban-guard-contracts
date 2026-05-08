//! VULNERABLE: Missing unlock ledger monotonicity checks in time-lock contracts.
//!
//! If `unlock_ledger` is set to the current or a past sequence, withdrawals become
//! immediately possible and the lock is effectively bypassed.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const MIN_LOCK_DURATION: u32 = 100;

#[contracttype]
pub enum DataKey {
    Amount(Address),
    UnlockLedger(Address),
}

#[contract]
pub struct VulnerableTimelockSequence;

#[contractimpl]
impl VulnerableTimelockSequence {
    pub fn lock(env: Env, user: Address, amount: i128, unlock_ledger: u32) {
        user.require_auth();

        let current_sequence = env.ledger().sequence();
        if unlock_ledger <= current_sequence {
            panic!("unlock_ledger must be in the future");
        }
        if unlock_ledger - current_sequence < MIN_LOCK_DURATION {
            panic!("minimum lock duration is 100 ledgers");
        }

        env.storage()
            .persistent()
            .set(&DataKey::UnlockLedger(user.clone()), &unlock_ledger);
        env.storage()
            .persistent()
            .set(&DataKey::Amount(user), &amount);
    }

    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();

        let unlock_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::UnlockLedger(user.clone()))
            .expect("unlock ledger not set");

        if env.ledger().sequence() < unlock_ledger {
            panic!("still locked");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Amount(user.clone()), &0i128);
        env.storage()
            .persistent()
            .remove(&DataKey::UnlockLedger(user));
    }

    pub fn amount(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Amount(user))
            .unwrap_or(0)
    }

    pub fn unlock_ledger(env: Env, user: Address) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::UnlockLedger(user))
    }

    pub fn current_sequence(env: Env) -> u32 {
        env.ledger().sequence()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    fn setup() -> (Env, VulnerableTimelockSequenceClient<'static>) {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableTimelockSequence);
        let client = VulnerableTimelockSequenceClient::new(&env, &contract_id);
        (env, client)
    }

    fn vulnerable_withdraw_allowed(current_sequence: u32, unlock_ledger: u32) -> bool {
        // Mirrors the vulnerable check: only `current >= unlock` is checked at withdraw time,
        // but lock-time validation is missing.
        current_sequence >= unlock_ledger
    }

    #[test]
    fn test_bug_locking_at_current_sequence_allows_immediate_withdrawal() {
        let current = 500u32;
        let unlock_ledger = current;

        assert!(vulnerable_withdraw_allowed(current, unlock_ledger));
    }

    #[test]
    #[should_panic(expected = "unlock_ledger must be in the future")]
    fn test_lock_with_unlock_ledger_not_in_future_panics_after_fix() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        let current = env.ledger().sequence();
        client.lock(&user, &1_000, &current);
    }

    #[test]
    fn test_valid_future_unlock_prevents_withdraw_until_reached() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        env.mock_all_auths();

        env.ledger().set_sequence_number(1_000);
        let unlock_ledger = 1_000 + MIN_LOCK_DURATION;
        client.lock(&user, &10_000, &unlock_ledger);

        let early_withdraw = std::panic::catch_unwind(|| client.withdraw(&user));
        assert!(early_withdraw.is_err());
        assert_eq!(client.amount(&user), 10_000);

        env.ledger().set_sequence_number(unlock_ledger);
        client.withdraw(&user);
        assert_eq!(client.amount(&user), 0);
        assert_eq!(client.unlock_ledger(&user), None);
    }
}
