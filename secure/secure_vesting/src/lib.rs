#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[derive(Clone)]
#[contracttype]
pub struct VestingSchedule {
    pub total: i128,
    pub claimed: i128,
    pub cliff_ledger: u32,
    pub end_ledger: u32,
    pub revoked_at: Option<u32>,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Treasury,
    TreasuryBalance,
    Schedule(Address),
}

#[contract]
pub struct SecureVesting;

#[contractimpl]
impl SecureVesting {
    pub fn initialize(env: Env, admin: Address, treasury: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Treasury, &treasury);
        env.storage()
            .persistent()
            .set(&DataKey::TreasuryBalance, &0i128);
    }

    pub fn create_schedule(
        env: Env,
        beneficiary: Address,
        total: i128,
        cliff_ledger: u32,
        end_ledger: u32,
    ) {
        Self::require_admin_auth(&env);
        if total <= 0 {
            panic!("total must be positive");
        }
        if cliff_ledger >= end_ledger {
            panic!("invalid schedule");
        }

        let key = DataKey::Schedule(beneficiary);
        if env.storage().persistent().has(&key) {
            panic!("schedule already exists");
        }

        let schedule = VestingSchedule {
            total,
            claimed: 0,
            cliff_ledger,
            end_ledger,
            revoked_at: None,
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

        if schedule.revoked_at.is_some() {
            panic!("schedule revoked");
        }

        let vested = Self::vested_for_schedule(&env, &schedule);
        if vested <= schedule.claimed {
            panic!("nothing claimable");
        }

        let claimable = vested - schedule.claimed;
        schedule.claimed = vested;
        env.storage().persistent().set(&key, &schedule);
        claimable
    }

    pub fn revoke(env: Env, beneficiary: Address) {
        Self::require_admin_auth(&env);

        let key = DataKey::Schedule(beneficiary);
        let mut schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&key)
            .expect("schedule not found");
        if schedule.revoked_at.is_some() {
            panic!("already revoked");
        }

        let now = env.ledger().sequence();
        let vested_now = Self::vested_for_schedule(&env, &schedule);
        let unvested = schedule.total - vested_now;

        let current_treasury_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TreasuryBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TreasuryBalance, &(current_treasury_balance + unvested));

        schedule.revoked_at = Some(now);
        env.storage().persistent().set(&key, &schedule);
    }

    pub fn vested_amount(env: Env, beneficiary: Address) -> i128 {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        Self::vested_for_schedule(&env, &schedule)
    }

    pub fn get_position(env: Env, beneficiary: Address) -> (i128, i128, bool) {
        let schedule: VestingSchedule = env
            .storage()
            .persistent()
            .get(&DataKey::Schedule(beneficiary))
            .expect("schedule not found");
        (
            schedule.total,
            schedule.claimed,
            schedule.revoked_at.is_some(),
        )
    }

    pub fn treasury_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TreasuryBalance)
            .unwrap_or(0)
    }

    fn vested_for_schedule(env: &Env, schedule: &VestingSchedule) -> i128 {
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
    extern crate std;

    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::Ledger as _, Address, Env};

    fn setup() -> (Env, SecureVestingClient<'static>, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVesting);
        let client = SecureVestingClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        let treasury = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        (env, client, admin, treasury, beneficiary)
    }

    #[test]
    fn test_vested_amount_is_zero_before_cliff() {
        let (env, client, admin, treasury, beneficiary) = setup();
        env.mock_all_auths();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &treasury);
        client.create_schedule(&beneficiary, &1_000, &200, &400);

        env.ledger().set_sequence_number(150);
        assert_eq!(client.vested_amount(&beneficiary), 0);
    }

    #[test]
    fn test_vested_amount_is_full_at_or_after_end_ledger() {
        let (env, client, admin, treasury, beneficiary) = setup();
        env.mock_all_auths();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &treasury);
        client.create_schedule(&beneficiary, &2_000, &200, &400);

        env.ledger().set_sequence_number(400);
        assert_eq!(client.vested_amount(&beneficiary), 2_000);

        env.ledger().set_sequence_number(450);
        assert_eq!(client.vested_amount(&beneficiary), 2_000);
    }

    #[test]
    fn test_admin_revoke_moves_unvested_to_treasury_and_blocks_claims() {
        let (env, client, admin, treasury, beneficiary) = setup();
        env.mock_all_auths();
        env.ledger().set_sequence_number(100);

        client.initialize(&admin, &treasury);
        client.create_schedule(&beneficiary, &1_000, &200, &400);

        // At ledger 250, vested = 1000 * (250 - 200) / (400 - 200) = 250, unvested = 750.
        env.ledger().set_sequence_number(250);
        client.revoke(&beneficiary);
        assert_eq!(client.treasury_balance(), 750);

        let claim_attempt = std::panic::catch_unwind(|| {
            client.claim(&beneficiary);
        });
        assert!(claim_attempt.is_err());
    }
}
