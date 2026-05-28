//! SECURE: Vesting Claim Subtracts Previously Claimed Amount
//!
//! Computes `claimable = vested - claimed` and updates the claimed record
//! before returning the payout.

use super::{vested_for_schedule, DataKey, VestingSchedule};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVesting;

#[contractimpl]
impl SecureVesting {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn create_schedule(
        env: Env,
        beneficiary: Address,
        total: i128,
        cliff_ledger: u32,
        end_ledger: u32,
    ) {
        Self::require_admin_auth(&env);
        let key = DataKey::Schedule(beneficiary.clone());
        if env.storage().persistent().has(&key) {
            panic!("schedule already exists");
        }
        let schedule = VestingSchedule {
            total,
            claimed: 0,
            cliff_ledger,
            end_ledger,
        };
        env.storage().persistent().set(&key, &schedule);
    }

    /// ✅ Subtracts previously claimed amount and records the new claimed total.
    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();
        let key = DataKey::Schedule(beneficiary);
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        let vested = vested_for_schedule(&env, &schedule);
        if vested <= schedule.claimed {
            panic!("nothing claimable");
        }

        let claimable = vested - schedule.claimed;
        schedule.claimed = vested;
        env.storage().persistent().set(&key, &schedule);
        claimable
    }

    pub fn claimed_amount(env: Env, beneficiary: Address) -> i128 {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        schedule.claimed
    }

    fn require_admin_auth(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        admin.require_auth();
    }
}
