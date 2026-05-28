//! SECURE: Revoked Vesting Schedule Cannot Be Claimed
//!
//! Rejects claims when the schedule has been revoked.

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
            revoked: false,
            revoked_at: None,
        };
        env.storage().persistent().set(&key, &schedule);
    }

    pub fn revoke(env: Env, beneficiary: Address) {
        Self::require_admin_auth(&env);
        let key = DataKey::Schedule(beneficiary);
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");
        if schedule.revoked {
            panic!("already revoked");
        }
        schedule.revoked = true;
        schedule.revoked_at = Some(env.ledger().sequence());
        env.storage().persistent().set(&key, &schedule);
    }

    /// ✅ Rejects claims on revoked schedules.
    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();
        let key = DataKey::Schedule(beneficiary);
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        if schedule.revoked {
            panic!("schedule revoked");
        }

        let vested = vested_for_schedule(&env, &schedule);
        if vested <= schedule.claimed {
            return 0;
        }
        let claimable = vested - schedule.claimed;
        schedule.claimed = vested;
        env.storage().persistent().set(&key, &schedule);
        claimable
    }

    pub fn is_revoked(env: Env, beneficiary: Address) -> bool {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        schedule.revoked
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
