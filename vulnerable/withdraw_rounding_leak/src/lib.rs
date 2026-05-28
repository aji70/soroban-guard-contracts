//! VULNERABLE: Withdrawal Rounding Leak
//!
//! A vault computes `shares_to_burn = assets_requested * total_shares / total_assets`.
//! Integer division floors the result in favour of the withdrawer.  Repeated
//! small withdrawals extract assets while burning fewer shares than the
//! proportional amount, slowly draining value from other depositors.
//!
//! VULNERABILITY: `withdraw` does not round `shares_to_burn` up, and does not
//! reject withdrawals whose computed burn is zero.
//!
//! SEVERITY: High
//!
//! SECURE MIRROR: `secure::SecureVault` rounds `shares_to_burn` up (ceiling
//! division) and panics when the result is zero.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    TotalAssets,
    TotalShares,
    Shares(Address),
}

#[contract]
pub struct WithdrawRoundingVault;

#[contractimpl]
impl WithdrawRoundingVault {
    pub fn initialize(env: Env, seed_assets: i128, seed_shares: i128) {
        assert!(seed_assets > 0 && seed_shares > 0, "seed must be positive");
        if env.storage().persistent().has(&DataKey::TotalAssets) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::TotalAssets, &seed_assets);
        env.storage().persistent().set(&DataKey::TotalShares, &seed_shares);
    }

    /// Seed a user's share balance directly (test helper).
    pub fn seed_shares(env: Env, user: Address, shares: i128) {
        env.storage().persistent().set(&DataKey::Shares(user), &shares);
    }

    /// VULNERABLE: `shares_to_burn` floors in favour of the withdrawer.
    pub fn withdraw(env: Env, user: Address, assets: i128) {
        user.require_auth();
        assert!(assets > 0, "assets must be positive");

        let total_assets: i128 = env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(1);
        let total_shares: i128 = env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(1);

        // ❌ Floor division — withdrawer pays fewer shares than they should.
        let shares_to_burn = assets * total_shares / total_assets;

        // ❌ Missing: assert!(shares_to_burn > 0, "withdrawal burns zero shares");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        assert!(current >= shares_to_burn, "insufficient shares");

        env.storage()
            .persistent()
            .set(&DataKey::Shares(user), &(current - shares_to_burn));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(total_assets - assets));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares - shares_to_burn));
    }

    pub fn shares_of(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Shares(user))
            .unwrap_or(0)
    }

    pub fn total_shares(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(0)
    }

    pub fn total_assets(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (WithdrawRoundingVaultClient, Address) {
        let id = env.register_contract(None, WithdrawRoundingVault);
        let client = WithdrawRoundingVaultClient::new(env, &id);
        env.mock_all_auths();
        // 1000 assets, 1000 shares → 1:1 share price.
        client.initialize(&1000, &1000);
        let user = Address::generate(env);
        // Give user 500 shares.
        client.seed_shares(&user, &500);
        (client, user)
    }

    /// DEMONSTRATES VULNERABILITY: repeated 1-asset withdrawals burn zero shares.
    #[test]
    fn test_repeated_withdrawals_drain_assets_without_burning_shares() {
        let env = Env::default();
        let (client, user) = setup(&env);
        env.mock_all_auths();

        // With 1000 assets and 1000 shares, withdrawing 1 asset should burn 1 share.
        // But if we manipulate the ratio first (inflate assets without shares),
        // we can make shares_to_burn floor to 0.
        //
        // Simulate inflated asset pool: 10_000 assets, 10 shares.
        let id2 = env.register_contract(None, WithdrawRoundingVault);
        let c2 = WithdrawRoundingVaultClient::new(&env, &id2);
        c2.initialize(&10_000, &10); // share price = 1000 assets/share
        let u2 = Address::generate(&env);
        c2.seed_shares(&u2, &10);

        let shares_before = c2.shares_of(&u2);
        let assets_before = c2.total_assets();

        // Withdraw 1 asset: shares_to_burn = 1 * 10 / 10_000 = 0 (floors).
        c2.withdraw(&u2, &1);

        assert_eq!(c2.shares_of(&u2), shares_before, "no shares burned");
        assert_eq!(c2.total_assets(), assets_before - 1, "assets decreased");
    }

    /// Boundary: withdrawal that burns zero shares is accepted by the vulnerable contract.
    #[test]
    fn test_zero_burn_withdrawal_accepted() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, WithdrawRoundingVault);
        let client = WithdrawRoundingVaultClient::new(&env, &id);
        client.initialize(&10_000, &10);
        let user = Address::generate(&env);
        client.seed_shares(&user, &10);

        // shares_to_burn = 1 * 10 / 10_000 = 0 — should be rejected but isn't.
        client.withdraw(&user, &1);
        assert_eq!(client.shares_of(&user), 10, "shares unchanged after zero-burn withdrawal");
    }

    /// SECURE: withdrawal that would burn zero shares is rejected.
    #[test]
    #[should_panic(expected = "withdrawal burns zero shares")]
    fn test_secure_rejects_zero_burn_withdrawal() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&10_000, &10);
        let user = Address::generate(&env);
        client.seed_shares(&user, &10);

        client.withdraw(&user, &1);
    }

    /// SECURE: proportional withdrawal burns the correct (ceiling) number of shares.
    #[test]
    fn test_secure_proportional_withdrawal() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        env.mock_all_auths();
        // 1000 assets, 1000 shares → 1:1.
        client.initialize(&1000, &1000);
        let user = Address::generate(&env);
        client.seed_shares(&user, &500);

        client.withdraw(&user, &100);
        // 100 * 1000 / 1000 = 100 shares burned (exact, ceiling == floor here).
        assert_eq!(client.shares_of(&user), 400);
        assert_eq!(client.total_assets(), 900);
    }
}
