//! VULNERABLE: Self-Stake / Circular Balance Entry
//!
//! A staking contract where `stake`, `unstake`, and `claim_rewards` do not
//! validate that the staker differs from `env.current_contract_address()`.
//! If the contract is invoked with itself as the staker (e.g. via a
//! cross-contract call), it creates a circular balance entry: the contract
//! holds a stake in itself, distorting total-supply calculations and
//! potentially enabling reward extraction without real token backing.
//!
//! VULNERABILITY: Missing `staker != env.current_contract_address()` guard in
//! `stake`, `unstake`, and `claim_rewards`.
//!
//! SEVERITY: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Stake(Address),
    StakedAt(Address),
    RewardRate,
}

pub fn get_stake(env: &Env, staker: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Stake(staker.clone()))
        .unwrap_or(0)
}

pub fn set_stake(env: &Env, staker: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Stake(staker.clone()), &amount);
}

pub fn get_staked_at(env: &Env, staker: &Address) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::StakedAt(staker.clone()))
        .unwrap_or(0)
}

pub fn set_staked_at(env: &Env, staker: &Address, seq: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::StakedAt(staker.clone()), &seq);
}

pub fn get_rate(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::RewardRate)
        .unwrap_or(0)
}

#[contract]
pub struct SelfStake;

#[contractimpl]
impl SelfStake {
    pub fn initialize(env: Env, reward_rate: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    /// VULNERABLE: does not check `staker != env.current_contract_address()`.
    /// A cross-contract call can pass the contract's own address as `staker`,
    /// creating a circular balance entry.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ❌ Missing: if staker == env.current_contract_address() { panic!(...) }
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let current = get_stake(&env, &staker);
        set_stake(&env, &staker, current + amount);
        set_staked_at(&env, &staker, env.ledger().sequence());
    }

    /// VULNERABLE: same missing guard — contract can unstake from itself.
    pub fn unstake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ❌ Missing: if staker == env.current_contract_address() { panic!(...) }
        let current = get_stake(&env, &staker);
        let new_balance = current.checked_sub(amount).expect("insufficient stake");
        set_stake(&env, &staker, new_balance);
    }

    /// VULNERABLE: same missing guard — contract can claim rewards for itself.
    pub fn claim_rewards(env: Env, staker: Address) -> i128 {
        staker.require_auth();
        // ❌ Missing: if staker == env.current_contract_address() { panic!(...) }
        let elapsed = (env.ledger().sequence() - get_staked_at(&env, &staker)) as i128;
        let reward = get_stake(&env, &staker)
            .checked_mul(get_rate(&env))
            .and_then(|v| v.checked_mul(elapsed))
            .unwrap_or(0);
        set_staked_at(&env, &staker, env.ledger().sequence());
        reward
    }

    pub fn get_stake(env: Env, staker: Address) -> i128 {
        get_stake(&env, &staker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, SelfStakeClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SelfStake);
        let client = SelfStakeClient::new(&env, &id);
        client.initialize(&10);
        (env, id, client)
    }

    /// Demonstrates the vulnerability: the contract address is accepted as a
    /// staker, creating a circular balance entry.
    #[test]
    fn test_contract_can_stake_to_itself() {
        let (env, id, client) = setup();

        // Pass the contract's own address as the staker — this should be
        // rejected by a secure contract but succeeds here.
        client.stake(&id, &500);
        assert_eq!(client.get_stake(&id), 500, "contract staked to itself");
    }

    /// Normal user staking is unaffected.
    #[test]
    fn test_normal_user_stake_works() {
        let (env, _id, client) = setup();
        let alice = Address::generate(&env);

        client.stake(&alice, &1_000);
        assert_eq!(client.get_stake(&alice), 1_000);
    }

    /// Secure version rejects the contract address as staker.
    #[test]
    #[should_panic(expected = "contract cannot stake to itself")]
    fn test_secure_rejects_self_stake() {
        use crate::secure::SecureStakeClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStake);
        let client = SecureStakeClient::new(&env, &id);
        client.initialize(&10);

        // Must panic — contract address is not a valid staker.
        client.stake(&id, &500);
    }

    /// Secure version rejects the contract address in unstake.
    #[test]
    #[should_panic(expected = "contract cannot stake to itself")]
    fn test_secure_rejects_self_unstake() {
        use crate::secure::SecureStakeClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStake);
        let client = SecureStakeClient::new(&env, &id);
        client.initialize(&10);

        client.unstake(&id, &100);
    }

    /// Secure version rejects the contract address in claim_rewards.
    #[test]
    #[should_panic(expected = "contract cannot stake to itself")]
    fn test_secure_rejects_self_claim() {
        use crate::secure::SecureStakeClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStake);
        let client = SecureStakeClient::new(&env, &id);
        client.initialize(&10);

        client.claim_rewards(&id);
    }

    /// Secure version still allows normal users to stake, unstake, and claim.
    #[test]
    fn test_secure_normal_user_unaffected() {
        use crate::secure::SecureStakeClient;
        use soroban_sdk::testutils::Ledger;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStake);
        let client = SecureStakeClient::new(&env, &id);
        client.initialize(&10);

        let alice = Address::generate(&env);
        client.stake(&alice, &1_000);
        assert_eq!(client.get_stake(&alice), 1_000);

        env.ledger().with_mut(|l| l.sequence_number += 5);
        let reward = client.claim_rewards(&alice);
        // reward = 1000 * 10 * 5 = 50_000
        assert_eq!(reward, 50_000);

        client.unstake(&alice, &1_000);
        assert_eq!(client.get_stake(&alice), 0);
    }
}
