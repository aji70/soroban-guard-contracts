//! VULNERABLE: Vesting Schedule Allows Cliff After End Ledger
//!
//! The vesting initializer accepts any combination of `start_ledger`,
//! `cliff_ledger`, and `end_ledger` without validating their relative order.
//! When `cliff_ledger > end_ledger`, claims produce incorrect math or lock funds.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[derive(Clone)]
#[contracttype]
pub struct VestingSchedule {
    pub total: i128,
    pub claimed: i128,
    pub start_ledger: u32,
    pub cliff_ledger: u32,
    pub end_ledger: u32,
}

#[contracttype]
pub enum DataKey {
    Schedule(Address),
}

#[contract]
pub struct VulnerableVesting;

#[contractimpl]
impl VulnerableVesting {
    /// ❌ Stores inverted schedules without validation.
    pub fn initialize(
        env: Env,
        beneficiary: Address,
        total: i128,
        start_ledger: u32,
        cliff_ledger: u32,
        end_ledger: u32,
    ) {
        let schedule = VestingSchedule {
            total,
            claimed: 0,
            start_ledger,
            cliff_ledger,
            end_ledger,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Schedule(beneficiary), &schedule);
    }

    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();

        let key = DataKey::Schedule(beneficiary);
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        let vested = Self::vested_for_schedule(&env, &schedule);
        assert!(vested > schedule.claimed, "nothing claimable");

        let claimable = vested - schedule.claimed;
        schedule.claimed = vested;
        env.storage().persistent().set(&key, &schedule);
        claimable
    }

    pub fn vested_amount(env: Env, beneficiary: Address) -> i128 {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        Self::vested_for_schedule(&env, &schedule)
    }

    fn vested_for_schedule(env: &Env, schedule: &VestingSchedule) -> i128 {
        let now = env.ledger().sequence();
        if now < schedule.cliff_ledger {
            return 0;
        }
        if now >= schedule.end_ledger {
            return schedule.total;
        }
        let elapsed = (now - schedule.cliff_ledger) as i128;
        let duration = (schedule.end_ledger - schedule.cliff_ledger) as i128;
        schedule.total * elapsed / duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::SecureVestingClient;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    const TOTAL: i128 = 1_000;
    const START: u32 = 100;
    const END: u32 = 400;

    fn setup_vulnerable(
        env: &Env,
        cliff: u32,
    ) -> (VulnerableVestingClient<'_>, Address) {
        let beneficiary = Address::generate(env);
        let contract_id = env.register_contract(None, VulnerableVesting);
        let client = VulnerableVestingClient::new(env, &contract_id);
        client.initialize(&beneficiary, &TOTAL, &START, &cliff, &END);
        (client, beneficiary)
    }

    #[test]
    #[should_panic(expected = "nothing claimable")]
    fn test_vulnerable_inverted_schedule_locks_funds() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(350);

        let (client, beneficiary) = setup_vulnerable(&env, END + 100);
        assert_eq!(client.vested_amount(&beneficiary), 0);
        client.claim(&beneficiary);
    }

    #[test]
    #[should_panic(expected = "nothing claimable")]
    fn test_vulnerable_boundary_cliff_one_past_end() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(END);

        let (client, beneficiary) = setup_vulnerable(&env, END + 1);
        assert_eq!(client.vested_amount(&beneficiary), 0);
        client.claim(&beneficiary);
    }

    #[test]
    #[should_panic(expected = "invalid schedule")]
    fn test_secure_rejects_inverted_schedule() {
        let env = Env::default();
        env.mock_all_auths();

        let beneficiary = Address::generate(&env);
        let contract_id = env.register_contract(None, secure::SecureVesting);
        let client = SecureVestingClient::new(&env, &contract_id);

        client.initialize(&beneficiary, &TOTAL, &START, &(END + 1), &END);
    }
}
