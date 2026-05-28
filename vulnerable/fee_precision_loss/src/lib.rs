//! VULNERABLE: Fee Precision Loss via Integer Division Truncation
//!
//! A 1% fee (rate = 100 bps out of 10_000) floors to 0 for any transfer
//! amount < 100. An attacker splits a large transfer into many dust chunks,
//! each paying zero fee, bypassing the protocol fee entirely.
//!
//! VULNERABILITY: `fee = amount * FEE_BPS / 10_000` truncates to 0 when
//! `amount < 10_000 / FEE_BPS`. No minimum fee is enforced.
//!
//! SEVERITY: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

/// 1% fee expressed in basis points.
pub const FEE_BPS: i128 = 100;
pub const BPS_DENOM: i128 = 10_000;

#[contracttype]
pub enum DataKey {
    Balance(Address),
    FeesCollected,
}

pub(crate) fn balance_of(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

pub(crate) fn fees_collected(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::FeesCollected)
        .unwrap_or(0)
}

#[contract]
pub struct VulnerableFeeContract;

#[contractimpl]
impl VulnerableFeeContract {
    pub fn mint(env: Env, user: Address, amount: i128) {
        assert!(amount > 0);
        let bal = balance_of(&env, &user);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(user), &(bal + amount));
    }

    /// VULNERABLE: fee floors to 0 for small amounts.
    ///
    /// # Vulnerability
    /// `fee = amount * FEE_BPS / BPS_DENOM` — for amount < 100 this is 0.
    /// Splitting a large transfer into chunks of 99 pays zero total fees.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        assert!(amount > 0, "amount must be positive");

        // ❌ BUG: integer division truncates fee to 0 for small amounts.
        let fee = amount * FEE_BPS / BPS_DENOM;

        let from_bal = balance_of(&env, &from);
        assert!(from_bal >= amount, "insufficient balance");

        env.storage()
            .persistent()
            .set(&DataKey::Balance(from), &(from_bal - amount));

        let to_bal = balance_of(&env, &to);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(to), &(to_bal + amount - fee));

        let collected = fees_collected(&env);
        env.storage()
            .persistent()
            .set(&DataKey::FeesCollected, &(collected + fee));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        balance_of(&env, &user)
    }

    pub fn fees_collected(env: Env) -> i128 {
        fees_collected(&env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureFeeContractClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_vuln(env: &Env) -> VulnerableFeeContractClient {
        let id = env.register_contract(None, VulnerableFeeContract);
        VulnerableFeeContractClient::new(env, &id)
    }

    fn setup_secure(env: &Env) -> SecureFeeContractClient {
        let id = env.register_contract(None, secure::SecureFeeContract);
        SecureFeeContractClient::new(env, &id)
    }

    /// One large transfer of 10_000 collects 100 in fees (correct).
    #[test]
    fn test_single_large_transfer_collects_fee() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &10_000);

        client.transfer(&alice, &bob, &10_000);
        assert_eq!(client.fees_collected(), 100);
    }

    /// Demonstrates the vulnerability: 101 transfers of 99 units each
    /// (total = 9_999) collect 0 fees — attacker bypasses the 1% fee.
    #[test]
    fn test_split_transfers_bypass_fee() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        // Mint enough for 101 chunks of 99
        client.mint(&alice, &9_999);

        for _ in 0..101 {
            client.mint(&alice, &99); // top up per iteration for simplicity
            client.transfer(&alice, &bob, &99);
        }

        // ❌ Zero fees collected despite 101 non-zero transfers
        assert_eq!(client.fees_collected(), 0);
    }

    /// Boundary: a single transfer of 99 (below fee threshold) pays 0 fee.
    #[test]
    fn test_below_threshold_pays_zero_fee() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &99);

        client.transfer(&alice, &bob, &99);
        assert_eq!(client.fees_collected(), 0);
    }

    /// Secure: transfer of 99 still collects minimum fee of 1.
    #[test]
    fn test_secure_minimum_fee_enforced() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_secure(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &99);

        client.transfer(&alice, &bob, &99);
        // ✅ Minimum fee of 1 collected even for sub-threshold amounts
        assert_eq!(client.fees_collected(), 1);
    }

    /// Secure: split transfers still collect at least 1 fee per transfer.
    #[test]
    fn test_secure_split_transfers_collect_fees() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_secure(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        for _ in 0..10 {
            client.mint(&alice, &99);
            client.transfer(&alice, &bob, &99);
        }

        assert_eq!(client.fees_collected(), 10);
    }
}
