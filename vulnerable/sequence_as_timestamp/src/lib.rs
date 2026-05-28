//! VULNERABLE: Ledger sequence treated as timestamp units.
//!
//! A vesting-style lock that uses a duration expressed in seconds to compute an
//! unlock ledger sequence. Ledger sequence numbers are not seconds, so the lock
//! period becomes much longer or shorter than intended.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
    UnlockSequence(Address),
}

#[contract]
pub struct SequenceAsTimestampContract;

#[contractimpl]
impl SequenceAsTimestampContract {
    pub fn deposit(env: Env, user: Address, amount: i128, duration_seconds: u32) {
        user.require_auth();

        let balance_key = DataKey::Balance(user.clone());
        let current_balance: i128 = env.storage().persistent().get(&balance_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&balance_key, &(current_balance + amount));

        // BUG: treats `duration_seconds` as ledger sequence steps.
        let unlock_sequence = env.ledger().sequence() + duration_seconds;
        env.storage()
            .persistent()
            .set(&DataKey::UnlockSequence(user), &unlock_sequence);
    }

    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();

        let unlock_sequence: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::UnlockSequence(user.clone()))
            .expect("unlock not set");

        if env.ledger().sequence() < unlock_sequence {
            panic!("still locked");
        }

        env.storage().persistent().set(&DataKey::Balance(user.clone()), &0i128);
        env.storage().persistent().remove(&DataKey::UnlockSequence(user));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    pub fn unlock_sequence(env: Env, user: Address) -> Option<u32> {
        env.storage().persistent().get(&DataKey::UnlockSequence(user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Ledger as _, testutils::Address as _, Address, Env};

    #[test]
    fn test_vulnerable_lock_does_not_unlock_after_one_day_timestamp_advance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SequenceAsTimestampContract);
        let client = SequenceAsTimestampContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let duration = 86_400u32;

        env.mock_all_auths();
        client.deposit(&alice, &1000, &duration);

        let current_timestamp = env.ledger().timestamp();
        env.ledger().set_timestamp(current_timestamp + u64::from(duration));

        let result = std::panic::catch_unwind(|| client.withdraw(&alice));
        assert!(result.is_err());
        assert_eq!(client.balance(&alice), 1000);
    }

    #[test]
    fn test_secure_timestamp_lock_unlocks_after_one_day() {
        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureSequenceAsTimestampContract);
        let client = secure::SecureSequenceAsTimestampContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let duration = 86_400u32;

        env.mock_all_auths();
        client.deposit(&alice, &1000, &duration);

        let current_timestamp = env.ledger().timestamp();
        env.ledger().set_timestamp(current_timestamp + u64::from(duration));

        client.withdraw(&alice);
        assert_eq!(client.balance(&alice), 0);
    }
}
