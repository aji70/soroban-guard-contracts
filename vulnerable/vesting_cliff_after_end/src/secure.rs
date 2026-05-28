use soroban_sdk::{contract, contractimpl, Address, Env};

use super::{DataKey, VestingSchedule};

#[contract]
pub struct SecureVesting;

#[contractimpl]
impl SecureVesting {
    pub fn initialize(
        env: Env,
        beneficiary: Address,
        total: i128,
        start_ledger: u32,
        cliff_ledger: u32,
        end_ledger: u32,
    ) {
        assert!(total > 0, "total must be positive");
        assert!(start_ledger <= cliff_ledger, "invalid schedule");
        assert!(cliff_ledger <= end_ledger, "invalid schedule");
        assert!(start_ledger < end_ledger, "invalid schedule");

        let key = DataKey::Schedule(beneficiary.clone());
        assert!(
            !env.storage().persistent().has(&key),
            "schedule already exists"
        );

        let schedule = VestingSchedule {
            total,
            claimed: 0,
            start_ledger,
            cliff_ledger,
            end_ledger,
        };
        env.storage().persistent().set(&key, &schedule);
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
