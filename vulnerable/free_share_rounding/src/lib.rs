//! VULNERABLE: Free-Share Rounding
//!
//! A vault where `mint(shares)` calculates the required asset deposit as:
//!
//!   required = shares * total_assets / total_shares
//!
//! When `shares` is small relative to `total_shares / total_assets` (i.e. one
//! share costs less than one asset unit), integer division floors `required` to
//! zero.  The vault mints the requested shares and records a zero-asset deposit,
//! so the caller receives shares for free.
//!
//! VULNERABILITY: `mint` does not check that `required_assets > 0` before
//! crediting the caller with shares.
//!
//! SEVERITY: High
//!
//! SECURE MIRROR: `secure::SecureVault` uses ceiling division so every mint
//! of at least one share always costs at least one asset unit.

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
pub struct FreeShareVault;

#[contractimpl]
impl FreeShareVault {
    /// Seed the vault with initial assets and shares (sets the share price).
    pub fn initialize(env: Env, seed_assets: i128, seed_shares: i128) {
        assert!(seed_assets > 0 && seed_shares > 0, "seed must be positive");
        if env.storage().persistent().has(&DataKey::TotalAssets) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::TotalAssets, &seed_assets);
        env.storage().persistent().set(&DataKey::TotalShares, &seed_shares);
    }

    /// VULNERABLE: mints `shares` to `user` even when the required asset
    /// transfer rounds down to zero.
    pub fn mint(env: Env, user: Address, shares: i128) {
        user.require_auth();
        assert!(shares > 0, "shares must be positive");

        let total_assets: i128 = env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(1);
        let total_shares: i128 = env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(1);

        // ❌ Floor division: when shares * total_assets < total_shares, result is 0.
        let required_assets = shares * total_assets / total_shares;

        // ❌ Missing: assert!(required_assets > 0, "mint requires non-zero asset transfer");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Shares(user), &(current + shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(total_assets + required_assets));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares + shares));
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

    /// Seed: 1 asset, 1_000_000 shares → one share costs 0.000001 assets.
    /// Any mint of fewer than 1_000_000 shares requires < 1 asset → floors to 0.
    fn setup(env: &Env) -> FreeShareVaultClient {
        let id = env.register_contract(None, FreeShareVault);
        let client = FreeShareVaultClient::new(env, &id);
        env.mock_all_auths();
        client.initialize(&1, &1_000_000);
        client
    }

    /// DEMONSTRATES VULNERABILITY: user mints shares while paying zero assets.
    #[test]
    fn test_mint_free_shares_when_required_rounds_to_zero() {
        let env = Env::default();
        let client = setup(&env);

        let user = Address::generate(&env);
        // 1 share costs 1 / 1_000_000 assets → required = 1 * 1 / 1_000_000 = 0.
        client.mint(&user, &1);

        assert_eq!(client.shares_of(&user), 1, "user received shares");
        // Total assets unchanged — no assets were transferred.
        assert_eq!(client.total_assets(), 1, "vault received zero assets");
    }

    /// Boundary: minting up to 999_999 shares still costs zero assets.
    #[test]
    fn test_boundary_mint_below_threshold_costs_zero() {
        let env = Env::default();
        let client = setup(&env);

        let user = Address::generate(&env);
        // 999_999 * 1 / 1_000_000 = 0 (floors).
        client.mint(&user, &999_999);

        assert_eq!(client.shares_of(&user), 999_999);
        assert_eq!(client.total_assets(), 1, "still no assets paid");
    }

    /// SECURE: ceiling division charges at least 1 asset even for a tiny mint,
    /// so the vault's asset balance grows — no free shares.
    #[test]
    fn test_secure_charges_at_least_one_asset_for_tiny_mint() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&1, &1_000_000);

        let user = Address::generate(&env);
        // ceiling(1 * 1 / 1_000_000) = 1 — caller pays 1 asset, not 0.
        client.mint(&user, &1);

        assert_eq!(client.shares_of(&user), 1);
        assert_eq!(client.total_assets(), 2, "vault charged 1 asset");
    }
}
