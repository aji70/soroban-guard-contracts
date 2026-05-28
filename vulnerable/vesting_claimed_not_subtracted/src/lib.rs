//! VULNERABLE: Vesting Claim Does Not Subtract Previously Claimed Amount
//!
//! A vesting contract where `claim` transfers the full vested amount every time,
//! ignoring how much has already been claimed. Repeated claims drain the vault.
//!
//! VULNERABILITY: `claimable = vested` with no subtraction of `schedule.claimed`
//! and no update to the claimed record after payout.
//!
//! SECURE MIRROR: `secure::SecureVesting` computes `claimable = vested - claimed`
//! and updates `claimed` before returning the payout.

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
}

#[contracttype]
pub enum DataKey {
    Admin,
    Schedule(Address),
}

pub fn vested_for_schedule(env: &Env, schedule: &VestingSchedule) -> i128 {
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
        };
        env.storage().persistent().set(&key, &schedule);
    }

    /// VULNERABLE: pays the full vested amount on every call without subtracting
    /// previously claimed tokens or updating the claimed record.
    pub fn claim(env: Env, beneficiary: Address) -> i128 {
        beneficiary.require_auth();
        let key = DataKey::Schedule(beneficiary);
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");

        let vested = vested_for_schedule(&env, &schedule);
        // ❌ Missing: claimable = vested - schedule.claimed; update claimed record.
        vested
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
        env.ledger().set_sequence_number(300);
        (env, client, admin, beneficiary)
    }

    #[test]
    fn test_claim_once_after_cliff_succeeds() {
        let (_env, client, _admin, beneficiary) = setup();
        assert_eq!(client.claim(&beneficiary), 500);
    }

    #[test]
    fn test_second_claim_pays_full_vested_again() {
        let (_env, client, _admin, beneficiary) = setup();
        let first = client.claim(&beneficiary);
        let second = client.claim(&beneficiary);
        assert_eq!(first, 500);
        assert_eq!(second, 500, "vulnerable path pays full vested amount again");
    }

    #[test]
    #[should_panic(expected = "nothing claimable")]
    fn test_secure_second_claim_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVesting);
        let client = secure::SecureVestingClient::new(&env, &id);
        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        client.initialize(&admin);
        client.create_schedule(&beneficiary, &1_000, &200, &400);
        env.ledger().set_sequence_number(300);

        assert_eq!(client.claim(&beneficiary), 500);
        client.claim(&beneficiary);
    }
}
