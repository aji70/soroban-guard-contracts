//! VULNERABLE: No Minimum Stake Threshold
//!
//! A staking contract that accepts any positive amount, including dust-sized
//! stakes like 1 stroop. An attacker can create thousands of tiny stake
//! entries at negligible cost, bloating persistent storage and increasing
//! ledger fees for everyone.
//!
//! VULNERABILITY: `stake()` never enforces a minimum stake threshold.
//! SECURE MIRROR: `secure::SecureStaking` stores a configurable minimum stake
//! at initialization and rejects amounts below it.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

/// Default minimum stake used by the secure contract when initialized.
pub const MIN_STAKE: i128 = 1_000_000;

#[contracttype]
pub enum DataKey {
    Stake(Address),
    Admin,
    MinStake,
}

fn get_stake(env: &Env, staker: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(staker.clone()))
        .unwrap_or(0)
}

fn set_stake(env: &Env, staker: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Stake(staker.clone()), &amount);
}

#[contract]
pub struct VulnerableStaking;

#[contractimpl]
impl VulnerableStaking {
    /// VULNERABLE: accepts any positive amount, including dust.
    ///
    /// This creates storage pollution opportunities because even tiny stakes
    /// are recorded as persistent entries.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        assert!(amount > 0, "amount must be positive");
        let current = get_stake(&env, &staker);
        set_stake(&env, &staker, current + amount);
    }

    pub fn balance(env: Env, staker: Address) -> i128 {
        get_stake(&env, &staker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableStakingClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableStaking);
        let client = VulnerableStakingClient::new(&env, &id);
        let staker = Address::generate(&env);
        (env, client, staker)
    }

    /// Demonstrates the bug: a 1-stroop stake succeeds and records storage.
    #[test]
    fn test_one_stroop_succeeds() {
        let (_env, client, staker) = setup();

        client.stake(&staker, &1);

        assert_eq!(client.balance(&staker), 1);
    }

    /// Secure version rejects stakes below the configured minimum.
    #[test]
    #[should_panic(expected = "stake below minimum")]
    fn test_secure_rejects_below_minimum() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStaking);
        let client = secure::SecureStakingClient::new(&env, &id);
        let admin = Address::generate(&env);
        let staker = Address::generate(&env);

        client.initialize(&admin, &MIN_STAKE);
        client.stake(&staker, &(MIN_STAKE - 1));
    }

    /// Secure version accepts exactly MIN_STAKE.
    #[test]
    fn test_secure_accepts_exact_minimum() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStaking);
        let client = secure::SecureStakingClient::new(&env, &id);
        let admin = Address::generate(&env);
        let staker = Address::generate(&env);

        client.initialize(&admin, &MIN_STAKE);
        client.stake(&staker, &MIN_STAKE);

        assert_eq!(client.balance(&staker), MIN_STAKE);
    }
}
