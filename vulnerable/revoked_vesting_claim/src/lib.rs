//! VULNERABLE: Revoked Vesting Schedule Can Still Be Claimed
//!
//! A vesting contract where `claim` ignores the stored revocation flag and
//! pays out tokens even after an admin revokes the schedule.
//!
//! VULNERABILITY: `claim()` reads the schedule but performs no revocation check.
//!
//! SECURE MIRROR: `secure::SecureVesting` rejects claims when `revoked == true`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[derive(Clone)]
#[contracttype]
pub struct VestingSchedule {
    pub total: i128,
    pub claimed: i128,
    pub cliff_ledger: u32,
    pub end_ledger: u32,
    pub revoked: bool,
    pub revoked_at: Option<u32>,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Schedule(Address),
}

pub fn vested_for_schedule(env: &Env, schedule: &VestingSchedule) -> i128 {
    let now = env.ledger().sequence();
    let effective_now = match schedule.revoked_at {
        Some(revoked_at) if now > revoked_at => revoked_at,
        _ => now,
    };

    if effective_now < schedule.cliff_ledger {
        return 0;
    }
    if effective_now >= schedule.end_ledger {
        return schedule.total;
    }
    let elapsed = (effective_now - schedule.cliff_ledger) as i128;
    let duration = (schedule.end_ledger - schedule.cliff_ledger) as i128;
    schedule.total * elapsed / duration
}

#[contract]
pub struct VulnerableVesting;

#[contractimpl]
impl VulnerableVesting {
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

    /// VULNERABLE: no revocation check before paying out vested tokens.
    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();
        let key = DataKey::Schedule(beneficiary);
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        // ❌ Missing: if schedule.revoked { panic!("schedule revoked"); }
        let vested = vested_for_schedule(&env, &schedule);
        if vested <= schedule.claimed {
            return 0;
        }
        vested - schedule.claimed
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

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    fn setup() -> (Env, VulnerableVestingClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVesting);
        let client = VulnerableVestingClient::new(&env, &id);
        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        client.initialize(&admin);
        client.create_schedule(&beneficiary, &1_000, &200, &400);
        (env, client, admin, beneficiary)
    }

    #[test]
    fn test_revoked_schedule_still_claimable_after_advancing_ledgers() {
        let (env, client, _admin, beneficiary) = setup();
        env.ledger().set_sequence_number(250);
        client.revoke(&beneficiary);
        assert!(client.is_revoked(&beneficiary));

        env.ledger().set_sequence_number(350);
        let payout = client.claim(&beneficiary);
        assert!(payout > 0, "vulnerable path still pays after revocation");
    }

    #[test]
    fn test_claim_at_exact_revocation_ledger_allowed() {
        let (env, client, _admin, beneficiary) = setup();
        env.ledger().set_sequence_number(250);
        client.revoke(&beneficiary);

        let payout = client.claim(&beneficiary);
        assert!(payout > 0, "vulnerable path allows claim at revocation ledger");
    }

    #[test]
    #[should_panic(expected = "schedule revoked")]
    fn test_secure_rejects_claim_after_revocation() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVesting);
        let client = secure::SecureVestingClient::new(&env, &id);
        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        client.initialize(&admin);
        client.create_schedule(&beneficiary, &1_000, &200, &400);

        env.ledger().set_sequence_number(250);
        client.revoke(&beneficiary);
        env.ledger().set_sequence_number(350);
        client.claim(&beneficiary);
    }
}
