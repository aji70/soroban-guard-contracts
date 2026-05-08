//! SECURE: Staking With Amount Validation
//!
//! Identical API to VulnerableStaking but `stake` rejects zero and negative
//! amounts before touching persistent storage.

use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureStaking;

#[contractimpl]
impl SecureStaking {
    /// ✅ SECURE: rejects zero and negative amounts before updating storage.
    pub fn stake(env: Env, staker: Address, amount: i128) {
        staker.require_auth();
        // ✅ FIX: amount must be strictly positive.
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Stake(staker.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Returns the staked balance for `staker`.
    pub fn balance(env: Env, staker: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Stake(staker))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, SecureStakingClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureStaking);
        let client = SecureStakingClient::new(&env, &id);
        let staker = Address::generate(&env);
        (env, client, staker)
    }

    /// After the fix, staking zero panics.
    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_stake_zero_panics() {
        let (_env, client, staker) = setup();
        client.stake(&staker, &0);
    }

    /// After the fix, staking a negative amount panics.
    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_stake_negative_panics() {
        let (_env, client, staker) = setup();
        client.stake(&staker, &-1);
    }

    /// A valid positive stake succeeds and accumulates correctly.
    #[test]
    fn test_valid_stake_succeeds() {
        let (_env, client, staker) = setup();
        client.stake(&staker, &500);
        client.stake(&staker, &300);
        assert_eq!(client.balance(&staker), 800);
    }
}
