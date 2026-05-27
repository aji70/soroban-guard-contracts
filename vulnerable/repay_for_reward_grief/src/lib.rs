//! VULNERABLE: anyone may repay a borrower and reset their reward checkpoint.
//!
//! A third party can pay down a borrower's debt via `repay_for()` and the
//! contract will reset the borrower's reward checkpoint without preserving
//! accrued rewards. This erases pending rewards and alters the borrower's
//! reward accounting without their consent.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    RewardRate,
    Debt(Address),
    RewardCheckpoint(Address),
    AccruedReward(Address),
}

#[contract]
pub struct RepayForRewardGrief;

#[contractimpl]
impl RepayForRewardGrief {
    pub fn initialize(env: Env, admin: Address, reward_rate: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        if reward_rate <= 0 {
            panic!("reward_rate must be positive");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::RewardRate, &reward_rate);
    }

    pub fn borrow(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Debt(borrower.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
        env.storage()
            .persistent()
            .set(&DataKey::RewardCheckpoint(borrower), &env.ledger().timestamp());
    }

    /// Repay debt for another borrower.
    ///
    /// VULNERABILITY: resets the borrower's reward checkpoint without preserving
    /// accrued rewards, so pending rewards are erased by a third party.
    pub fn repay_for(env: Env, payer: Address, borrower: Address, amount: i128) {
        payer.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }
        let key = DataKey::Debt(borrower.clone());
        let debt: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if amount > debt {
            panic!("repay amount exceeds debt");
        }
        env.storage().persistent().set(&key, &(debt - amount));

        // ❌ BUG: reset checkpoint and throw away accrued reward history.
        env.storage()
            .persistent()
            .set(&DataKey::RewardCheckpoint(borrower), &env.ledger().timestamp());
    }

    pub fn claim_rewards(env: Env, borrower: Address) -> i128 {
        borrower.require_auth();
        let debt = Self::get_debt(&env, &borrower);
        let reward_rate = Self::get_reward_rate(&env);
        let last: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::RewardCheckpoint(borrower.clone()))
            .unwrap_or(env.ledger().timestamp());
        let elapsed = (env.ledger().timestamp() - last) as i128;
        let accrued: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::AccruedReward(borrower.clone()))
            .unwrap_or(0);
        let reward = accrued + debt * reward_rate * elapsed;
        env.storage()
            .persistent()
            .set(&DataKey::AccruedReward(borrower), &0i128);
        env.storage()
            .persistent()
            .set(&DataKey::RewardCheckpoint(borrower), &env.ledger().timestamp());
        reward
    }

    fn get_debt(env: &Env, borrower: &Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Debt(borrower.clone()))
            .unwrap_or(0)
    }

    fn get_reward_rate(env: &Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RewardRate)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::SecureRepayForRewardGriefClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, RepayForRewardGriefClient<'static>, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let attacker = Address::generate(&env);
        let id = env.register_contract(None, RepayForRewardGrief);
        let client = RepayForRewardGriefClient::new(&env, &id);
        (env, client, admin, borrower, attacker)
    }

    #[test]
    fn test_third_party_repay_erases_pending_rewards() {
        let (env, client, admin, borrower, attacker) = setup();
        client.initialize(&admin, &1);
        client.borrow(&borrower, &100);

        env.ledger().with_mut(|l| l.timestamp += 10);
        client.repay_for(&attacker, &borrower, &10);

        // After third-party repayment, the reward checkpoint is reset and the
        // borrower's accrued reward from the previous interval is lost.
        assert_eq!(client.claim_rewards(&borrower), 0);
    }

    #[test]
    fn test_secure_repay_for_preserves_pending_rewards() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let borrower = Address::generate(&env);
        let attacker = Address::generate(&env);
        let id = env.register_contract(None, secure::SecureRepayForRewardGrief);
        let client = SecureRepayForRewardGriefClient::new(&env, &id);

        client.initialize(&admin, &1);
        client.borrow(&borrower, &100);
        env.ledger().with_mut(|l| l.timestamp += 10);

        client.repay_for(&attacker, &borrower, &10);
        assert_eq!(client.claim_rewards(&borrower), 100);
    }
}
