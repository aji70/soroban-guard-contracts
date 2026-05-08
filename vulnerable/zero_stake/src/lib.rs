//! VULNERABLE: Zero-Amount Stake
//!
//! A staking contract where `stake(staker, 0)` succeeds and records a
//! `staked_at` timestamp. The staker occupies a storage slot and is treated
//! as a valid staker by any logic that checks `is_staker`, even though they
//! contributed nothing.
//!
//! `claim_rewards` returns `0 * rate * elapsed = 0`, so there is no direct
//! financial gain here, but the ghost entry can be exploited by future logic
//! that gates access on staker status (e.g. governance, airdrops).
//!
//! VULNERABILITY: Missing `assert!(amount > 0, "stake must be positive")`.
//! Severity: Medium
//!
//! Secure mirror: `secure::SecureStaking` rejects zero-amount stakes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Types ────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct StakeInfo {
    pub amount: i128,
    pub staked_at: u64,
}

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Stake(Address),
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableStaking;

#[contractimpl]
impl VulnerableStaking {
    /// VULNERABLE: records a stake entry even when `amount` is zero.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ❌ Missing: assert!(amount > 0, "stake must be positive");
        env.storage().persistent().set(
            &DataKey::Stake(staker),
            &StakeInfo {
                amount,
                staked_at: env.ledger().timestamp(),
            },
        );
    }

    /// Returns the elapsed-time reward for `staker` (amount × elapsed seconds).
    /// Returns 0 if no stake exists.
    pub fn claim_rewards(env: Env, staker: Address) -> i128 {
        let info: StakeInfo = env
            .storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .expect("no stake found");
        let elapsed = env.ledger().timestamp().saturating_sub(info.staked_at) as i128;
        info.amount * elapsed
    }

    /// Returns `true` if a stake entry exists for `staker`, regardless of amount.
    ///
    /// # Vulnerability
    /// Because zero-amount stakes are accepted, this can return `true` for accounts
    /// that contributed nothing — enabling ghost staker exploitation in governance or airdrops.
    pub fn is_staker(env: Env, staker: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::Stake(staker))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Normal stake records the correct amount and marks the address as a staker.
    #[test]
    fn test_normal_stake() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableStaking);
        let client = VulnerableStakingClient::new(&env, &id);

        let user = Address::generate(&env);
        client.stake(&user, &1000);
        assert!(client.is_staker(&user));
        assert_eq!(client.claim_rewards(&user), 0); // no time elapsed
    }

    /// DEMONSTRATES VULNERABILITY: zero stake succeeds, records a staked_at
    /// timestamp, and marks the address as a staker with no actual contribution.
    #[test]
    fn test_zero_stake_records_timestamp() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableStaking);
        let client = VulnerableStakingClient::new(&env, &id);

        let attacker = Address::generate(&env);

        // Zero stake should be rejected but isn't.
        client.stake(&attacker, &0);

        // The attacker is now registered as a staker despite contributing nothing.
        assert!(
            client.is_staker(&attacker),
            "zero stake must not register a staker, but it did"
        );

        // Storage slot exists with amount = 0.
        env.as_contract(&id, || {
            let info: StakeInfo = env
                .storage()
                .persistent()
                .get(&DataKey::Stake(attacker.clone()))
                .unwrap();
            assert_eq!(info.amount, 0);
        });
    }

    /// Secure version rejects zero-amount stakes.
    #[test]
    #[should_panic(expected = "stake must be positive")]
    fn test_secure_rejects_zero_stake() {
        use crate::secure::SecureStakingClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureStaking);
        let client = SecureStakingClient::new(&env, &id);

        let user = Address::generate(&env);
        client.stake(&user, &0);
    }
}
