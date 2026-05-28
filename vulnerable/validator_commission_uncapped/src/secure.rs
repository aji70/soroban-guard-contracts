//! SECURE: Validator Commission Is Capped at 100%
//!
//! Fixed version that validates commission is within 0..=10000 bps
//! before storage and rejects distribution if the value is out of range.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    CommissionBps,
    TotalRewards,
}

#[contract]
pub struct StakingSecure;

#[contractimpl]
impl StakingSecure {
    /// Initialize contract.
    pub fn init(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::CommissionBps, &0i128);
        env.storage()
            .persistent()
            .set(&DataKey::TotalRewards, &0i128);
    }

    /// ✓ FIXED: Set commission with validation that it's <= 10000 bps.
    /// Rejects values above 10000 (100%).
    pub fn set_commission_secure(env: Env, commission_bps: i128) {
        // ✓ FIXED: validate commission is within bounds
        assert!(
            commission_bps >= 0 && commission_bps <= 10000,
            "Commission must be between 0 and 10000 basis points"
        );

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
    /// ✓ FIXED: validates commission before applying it.
    pub fn distribute_rewards_secure(env: Env, _validator_address: Address, total_rewards: i128) {
        let commission_bps: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CommissionBps)
            .unwrap_or(0);

        // ✓ FIXED: verify commission is valid before use
        assert!(
            commission_bps >= 0 && commission_bps <= 10000,
            "Invalid commission stored"
        );

        let validator_commission = (total_rewards * commission_bps) / 10000;
        let delegator_rewards = total_rewards - validator_commission;

        // Now safe: delegator_rewards will always be >= 0
        assert!(
            delegator_rewards >= 0,
            "Delegator rewards cannot be negative"
        );

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
    #[should_panic(expected = "Commission must be between 0 and 10000")]
    fn test_secure_rejects_commission_above_100_percent() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingSecure);
        let client = StakingSecureClient::new(&env, &contract_id);

        client.init();

        // Try to set commission to 15000 bps (150%) — should panic
        client.set_commission_secure(&15000);
    }

    #[test]
    fn test_secure_accepts_commission_exactly_100_percent() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingSecure);
        let client = StakingSecureClient::new(&env, &contract_id);

        client.init();

        // Set commission to 10000 bps (100%) — boundary, should work
        client.set_commission_secure(&10000);
        assert_eq!(client.get_commission(), 10000);

        let validator = Address::generate(&env);

        // Distribute 1000 in rewards
        // validator_commission = 1000 * 100% = 1000
        // delegator_rewards = 1000 - 1000 = 0 (valid)
        client.distribute_rewards_secure(&validator, &1000);

        assert_eq!(client.get_delegator_rewards(), 0);
    }

    #[test]
    fn test_secure_normal_commission_distribution() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingSecure);
        let client = StakingSecureClient::new(&env, &contract_id);

        client.init();

        // Set commission to 2000 bps (20%)
        client.set_commission_secure(&2000);

        let validator = Address::generate(&env);

        // Distribute 1000 in rewards
        // validator_commission = 1000 * 20% = 200
        // delegator_rewards = 1000 - 200 = 800
        client.distribute_rewards_secure(&validator, &1000);

        assert_eq!(client.get_delegator_rewards(), 800);
    }

    #[test]
    #[should_panic(expected = "Commission must be between 0 and 10000")]
    fn test_secure_rejects_negative_commission() {
        let env = Env::default();
        let contract_id = env.register_contract(None, StakingSecure);
        let client = StakingSecureClient::new(&env, &contract_id);

        client.init();

        // Try to set commission to -1000 — should panic
        client.set_commission_secure(&-1000);
    }
}
