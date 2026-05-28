//! VULNERABLE: Validator Commission Can Be Set Above Rewards Earned
//!
//! A staking contract where validator commission basis points (bps) are stored
//! and applied with no upper bound check. Commission values above 10000 bps (100%)
//! cause delegator rewards to underflow or go entirely to the validator.
//!
//! VULNERABILITY: No validation that commission <= 10000 bps before storage.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    CommissionBps,
    TotalRewards,
}

#[contract]
pub struct StakingVulnerable;

#[contractimpl]
impl StakingVulnerable {
    /// Initialize contract.
    pub fn init(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::CommissionBps, &0i128);
        env.storage()
            .persistent()
            .set(&DataKey::TotalRewards, &0i128);
    }

    /// VULNERABLE: Set commission with no upper bound check.
    /// Allows values > 10000 bps (100%).
    pub fn set_commission_vulnerable(env: Env, commission_bps: i128) {
        // ❌ VULNERABLE: no validation that commission_bps <= 10000
        env.storage()
            .persistent()
            .set(&DataKey::CommissionBps, &commission_bps);
    }

    /// Get current commission.
    pub fn get_commission(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CommissionBps)
            .unwrap_or(0)
    }

    /// Distribute rewards and apply commission.
    /// VULNERABLE: applies unchecked commission, causing underflow if > 100%.
    pub fn distribute_rewards_vulnerable(env: Env, _validator_address: Address, total_rewards: i128) {
        let commission_bps: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CommissionBps)
            .unwrap_or(0);

        // ❌ VULNERABLE: no check that commission_bps <= 10000
        // If commission_bps > 10000, validator_commission can exceed total_rewards
        let validator_commission = (total_rewards * commission_bps) / 10000;
        let delegator_rewards = total_rewards - validator_commission;

        // If validator_commission > total_rewards, delegator_rewards underflows (wraps around)
        // This could result in negative rewards or very large positive rewards due to i128 wrapping

        env.storage()
            .persistent()
            .set(&DataKey::TotalRewards, &delegator_rewards);
    }

    /// Get remaining rewards for delegators after commission.
    pub fn get_delegator_rewards(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalRewards)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_vulnerable_commission_above_100_percent() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingVulnerable);
        let client = StakingVulnerableClient::new(&env, &contract_id);

        client.init();

        // Set commission to 15000 bps (150% — above 100%)
        client.set_commission_vulnerable(&15000);
        assert_eq!(client.get_commission(), 15000);

        // Get validator address
        let validator = Address::generate(&env);

        // Distribute 1000 in rewards
        // With 150% commission, validator_commission = (1000 * 15000) / 10000 = 1500
        // delegator_rewards = 1000 - 1500 = -500 (underflow)
        client.distribute_rewards_vulnerable(&validator, &1000);

        // The delegator rewards should be negative or wrapped around
        let delegator_rewards = client.get_delegator_rewards();

        // Demonstrate the vulnerability: delegator_rewards is negative
        assert!(delegator_rewards < 0);
    }

    #[test]
    fn test_vulnerable_commission_boundary_exactly_100_percent() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingVulnerable);
        let client = StakingVulnerableClient::new(&env, &contract_id);

        client.init();

        // Set commission to exactly 10000 bps (100%)
        client.set_commission_vulnerable(&10000);

        let validator = Address::generate(&env);

        // Distribute 1000 in rewards
        // With 100% commission, validator_commission = (1000 * 10000) / 10000 = 1000
        // delegator_rewards = 1000 - 1000 = 0
        client.distribute_rewards_vulnerable(&validator, &1000);

        // Delegators get zero rewards (all goes to validator)
        let delegator_rewards = client.get_delegator_rewards();
        assert_eq!(delegator_rewards, 0);
    }

    #[test]
    fn test_vulnerable_commission_way_above_100_percent() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingVulnerable);
        let client = StakingVulnerableClient::new(&env, &contract_id);

        client.init();

        // Set commission to 50000 bps (500%)
        client.set_commission_vulnerable(&50000);

        let validator = Address::generate(&env);

        // Distribute 1000 in rewards
        // validator_commission = (1000 * 50000) / 10000 = 5000
        // delegator_rewards = 1000 - 5000 = -4000 (big underflow)
        client.distribute_rewards_vulnerable(&validator, &1000);

        let delegator_rewards = client.get_delegator_rewards();

        // Heavily negative due to the extreme commission
        assert!(delegator_rewards < -3000);
    }
}
