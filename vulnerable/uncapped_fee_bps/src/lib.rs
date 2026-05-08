//! VULNERABLE: Uncapped Fee Basis Points
//!
//! A fee contract that allows the admin to set `fee_bps` without an upper
//! bound. An attacker or compromised admin can set `fee_bps > 10_000`,
//! causing `calculate_fee` to return a fee that exceeds the principal, and
//! with large amounts the unchecked multiplication can overflow `i128`.
//!
//! VULNERABILITY: No `fee_bps <= 10_000` guard in `set_fee`, and
//! `calculate_fee` uses raw `*` / `/` with no overflow protection.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const MAX_FEE_BPS: i128 = 10_000;

#[contracttype]
pub enum DataKey {
    FeeBps,
    Admin,
}

#[contract]
pub struct FeeContract;

#[contractimpl]
impl FeeContract {
    pub fn initialize(env: Env, admin: Address, fee_bps: i128) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    /// VULNERABLE: no upper bound check on fee_bps.
    /// A malicious admin can set fee_bps > 10_000, making fees exceed 100%.
    pub fn set_fee(env: Env, fee_bps: i128) {
        Self::require_admin(&env);
        // ❌ No cap — fee_bps can exceed 10_000 (100%)
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    /// VULNERABLE: raw arithmetic — no overflow protection.
    pub fn calculate_fee(env: Env, amount: i128) -> i128 {
        let fee_bps: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0);
        // ❌ Unchecked multiplication can overflow for large amounts
        amount * fee_bps / 10_000
    }

    pub fn current_fee_bps(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .unwrap();
        admin.require_auth();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};
    use secure::SecureFeeContractClient;

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, FeeContract);
        let admin = Address::generate(&env);
        (env, contract_id, admin)
    }

    // ── Regression: prove the bug exists ────────────────────────────────────

    /// fee_bps = 15_000 (150%) is accepted and returns a fee > amount.
    #[test]
    fn test_regression_uncapped_fee_exceeds_principal() {
        let (env, contract_id, admin) = setup();
        let client = FeeContractClient::new(&env, &contract_id);

        client.initialize(&admin, &100);
        client.set_fee(&15_000); // 150% — should be rejected but isn't

        let amount: i128 = 1_000_000;
        let fee = client.calculate_fee(&amount);

        // Bug: fee (1_500_000) > amount (1_000_000)
        assert!(
            fee > amount,
            "regression: expected fee > amount when fee_bps=15000, got fee={fee}"
        );
    }

    // ── Fix verification: secure contract rejects fee_bps > 10_000 ──────────

    /// Secure set_fee panics when fee_bps > 10_000.
    #[test]
    #[should_panic]
    fn test_secure_rejects_fee_bps_above_10000() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureFeeContract);
        let client = SecureFeeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &100);
        client.set_fee(&10_001); // must panic
    }

    // ── Boundary: fee_bps = 10_000 (100%) is accepted and correct ───────────

    #[test]
    fn test_secure_boundary_fee_bps_10000() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureFeeContract);
        let client = SecureFeeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &100);
        client.set_fee(&10_000); // exactly 100% — must be accepted

        let amount: i128 = 500_000;
        let fee = client.calculate_fee(&amount);
        assert_eq!(fee, amount, "100% fee should equal the full amount");
    }

    // ── Zero state: fee_bps = 0 produces zero fee ────────────────────────────

    #[test]
    fn test_secure_zero_fee_bps() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureFeeContract);
        let client = SecureFeeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &0);

        let fee = client.calculate_fee(&1_000_000);
        assert_eq!(fee, 0, "zero fee_bps must produce zero fee");
    }

    // ── Normal operation ─────────────────────────────────────────────────────

    #[test]
    fn test_secure_normal_fee_calculation() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, secure::SecureFeeContract);
        let client = SecureFeeContractClient::new(&env, &contract_id);
        let admin = Address::generate(&env);

        client.initialize(&admin, &250); // 2.5%

        let fee = client.calculate_fee(&1_000_000);
        assert_eq!(fee, 25_000); // 2.5% of 1_000_000
    }
}
