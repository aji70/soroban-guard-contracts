//! VULNERABLE: Admin Skim of Unaccounted Donations
//!
//! A vault that tracks user deposits in an internal `total_accounted` ledger
//! entry. The admin can call `skim()` to withdraw any balance above that
//! accounting figure, treating the excess as "donations".
//!
//! VULNERABILITY: Because `total_accounted` can lag behind the real balance
//! (e.g. after fee accrual, rebases, or direct token transfers), `skim()` can
//! remove funds that users legitimately expect to redeem. The contract trusts
//! the live balance minus the accounted figure without an explicit donation
//! acceptance step.
//!
//! SECURE MIRROR: `secure::SecureSkimVault` requires donors to call
//! `donate()` explicitly. Only the amount recorded in `total_donations` may
//! be skimmed; unaccounted excess is never treated as admin-owned.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    /// Sum of all user deposits — the amount users can redeem.
    TotalAccounted,
    /// Simulated raw vault balance (deposits + any injected excess).
    RawBalance,
}

#[contract]
pub struct AdminSkimDonations;

#[contractimpl]
impl AdminSkimDonations {
    /// Initialise with an admin. Guards against re-initialisation.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::TotalAccounted, &0i128);
        env.storage().persistent().set(&DataKey::RawBalance, &0i128);
    }

    /// User deposits tokens. Both the raw balance and the accounted total grow.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");
        let acc: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalAccounted)
            .unwrap_or(0);
        let raw: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalAccounted, &(acc + amount));
        env.storage()
            .persistent()
            .set(&DataKey::RawBalance, &(raw + amount));
        env.events()
            .publish((symbol_short!("deposit"),), (user, amount));
    }

    /// Simulate accounting drift: inject `amount` into the raw balance without
    /// updating `total_accounted`. This represents fees, rebases, or a direct
    /// token transfer that bypasses the deposit path.
    pub fn inject_excess(env: Env, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let raw: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::RawBalance, &(raw + amount));
    }

    /// VULNERABLE: Admin skims `raw_balance - total_accounted` as "donations".
    ///
    /// Because `total_accounted` can lag (e.g. after `inject_excess`), this
    /// removes funds users expect to redeem. There is no explicit donation
    /// acceptance step — any unexplained excess is treated as admin-owned.
    pub fn skim(env: Env) -> i128 {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let raw: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0);
        let acc: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalAccounted)
            .unwrap_or(0);

        // ❌ Trusts live balance minus accounting without an explicit donation
        //    record. Any excess — including user-redeemable funds that lagged
        //    accounting — is treated as admin-owned.
        let skimmable = raw - acc;
        if skimmable <= 0 {
            return 0;
        }

        env.storage()
            .persistent()
            .set(&DataKey::RawBalance, &acc);
        env.events()
            .publish((symbol_short!("skim"),), (admin, skimmable));
        skimmable
    }

    /// Returns the amount a user could redeem (total_accounted).
    pub fn redeemable(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalAccounted)
            .unwrap_or(0)
    }

    /// Returns the simulated raw vault balance.
    pub fn raw_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, AdminSkimDonationsClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, AdminSkimDonations);
        let client = AdminSkimDonationsClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    /// Normal operation: no excess, skim returns 0.
    #[test]
    fn test_skim_zero_when_no_excess() {
        let (_env, _admin, client) = setup();
        let env = Env::default();
        let user = Address::generate(&env);
        client.deposit(&user, &1_000);
        assert_eq!(client.skim(), 0);
        assert_eq!(client.redeemable(), 1_000);
    }

    /// DEMONSTRATES VULNERABILITY: accounting drift lets admin skim user funds.
    ///
    /// After `inject_excess`, `raw_balance > total_accounted`. The admin skims
    /// the difference, but that excess came from a rebase/fee that users
    /// expected to be redeemable. The redeemable amount is now less than what
    /// users deposited relative to the raw balance.
    #[test]
    fn test_skim_removes_user_redeemable_funds() {
        let (_env, _admin, client) = setup();
        let env = Env::default();
        let user = Address::generate(&env);

        client.deposit(&user, &1_000);
        assert_eq!(client.redeemable(), 1_000);
        assert_eq!(client.raw_balance(), 1_000);

        // Simulate accounting drift (fee accrual / rebase / direct transfer).
        client.inject_excess(&400);
        assert_eq!(client.raw_balance(), 1_400);
        assert_eq!(client.redeemable(), 1_000); // accounting unchanged

        // Admin skims the 400 "excess" — but users expected that 400 too.
        let skimmed = client.skim();
        assert_eq!(skimmed, 400);

        // Raw balance is now back to 1_000, but the 400 is gone.
        assert_eq!(client.raw_balance(), 1_000);
        assert_eq!(client.redeemable(), 1_000);
        // ❌ Users lost 400 that was never explicitly donated.
    }

    /// Boundary: skim on a balanced vault returns 0 and leaves state intact.
    #[test]
    fn test_skim_boundary_balanced_vault() {
        let (_env, _admin, client) = setup();
        let env = Env::default();
        let user = Address::generate(&env);
        client.deposit(&user, &500);
        let skimmed = client.skim();
        assert_eq!(skimmed, 0);
        assert_eq!(client.redeemable(), 500);
        assert_eq!(client.raw_balance(), 500);
    }

    /// SECURE: explicit donation flow — only accepted donations can be skimmed.
    #[test]
    fn test_secure_skim_only_accepted_donations() {
        use crate::secure::SecureSkimVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureSkimVault);
        let client = SecureSkimVaultClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let user = Address::generate(&env);
        client.deposit(&user, &1_000);

        // Inject excess (simulates rebase / direct transfer).
        client.inject_excess(&400);

        // Without an explicit donate() call, skim returns 0.
        assert_eq!(client.skim(), 0);
        assert_eq!(client.redeemable(), 1_000);
        assert_eq!(client.raw_balance(), 1_400);
    }

    /// SECURE: after an explicit donation, only that amount is skimmable.
    #[test]
    fn test_secure_skim_after_explicit_donation() {
        use crate::secure::SecureSkimVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureSkimVault);
        let client = SecureSkimVaultClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let donor = Address::generate(&env);
        client.deposit(&donor, &1_000);
        client.donate(&donor, &200);

        let skimmed = client.skim();
        assert_eq!(skimmed, 200);
        assert_eq!(client.redeemable(), 1_000); // user deposits untouched
    }
}
