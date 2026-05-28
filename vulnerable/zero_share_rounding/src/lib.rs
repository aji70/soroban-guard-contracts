//! VULNERABLE: Zero-Share Rounding
//!
//! A vault that calculates shares as `amount * total_shares / total_assets`.
//! When `total_assets` is large relative to `amount`, integer division floors
//! the result to zero.  The deposit is accepted, the user loses their tokens,
//! and `total_assets` grows without a matching share issuance — diluting all
//! other depositors.
//!
//! VULNERABILITY: `deposit` does not check that `shares_minted > 0` before
//! crediting the depositor.
//!
//! SEVERITY: Medium
//!
//! SECURE MIRROR: `secure::SecureVault` panics with "deposit mints zero shares"
//! when the computed share amount is zero.

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
pub struct ZeroShareVault;

#[contractimpl]
impl ZeroShareVault {
    pub fn initialize(env: Env, seed_assets: i128, seed_shares: i128) {
        assert!(seed_assets > 0 && seed_shares > 0, "seed must be positive");
        if env.storage().persistent().has(&DataKey::TotalAssets) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::TotalAssets, &seed_assets);
        env.storage().persistent().set(&DataKey::TotalShares, &seed_shares);
    }

    /// VULNERABLE: accepts the deposit even when `shares_minted` rounds to zero.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let total_assets: i128 = env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(1);
        let total_shares: i128 = env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(1);

        // ❌ Integer division floors to zero when amount << total_assets / total_shares.
        let shares_minted = amount * total_shares / total_assets;

        // ❌ Missing: assert!(shares_minted > 0, "deposit mints zero shares");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(user.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Shares(user), &(current + shares_minted));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(total_assets + amount));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares + shares_minted));
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

    fn setup(env: &Env) -> ZeroShareVaultClient {
        let id = env.register_contract(None, ZeroShareVault);
        let client = ZeroShareVaultClient::new(env, &id);
        env.mock_all_auths();
        // Seed: 1_000_000 assets, 1_000 shares → share price = 1000 assets/share.
        client.initialize(&1_000_000, &1_000);
        client
    }

    /// DEMONSTRATES VULNERABILITY: tiny deposit mints zero shares, user loses funds.
    #[test]
    fn test_zero_shares_minted_on_tiny_deposit() {
        let env = Env::default();
        let client = setup(&env);
        env.mock_all_auths();

        let user = Address::generate(&env);
        // 1 asset deposited; share price is 1000 → shares = 1 * 1000 / 1_000_000 = 0.
        client.deposit(&user, &1);

        assert_eq!(client.shares_of(&user), 0, "user received zero shares");
        // But total_assets grew — user's deposit was absorbed with no shares issued.
        assert_eq!(client.total_assets(), 1_000_001);
    }

    /// Boundary: deposit just below the share-price threshold also yields zero shares.
    #[test]
    fn test_deposit_below_threshold_yields_zero_shares() {
        let env = Env::default();
        let client = setup(&env);
        env.mock_all_auths();

        let user = Address::generate(&env);
        // 999 assets → 999 * 1000 / 1_000_000 = 0 (floors).
        client.deposit(&user, &999);
        assert_eq!(client.shares_of(&user), 0);
    }

    /// SECURE: deposit that mints zero shares is rejected.
    #[test]
    #[should_panic(expected = "deposit mints zero shares")]
    fn test_secure_rejects_zero_share_deposit() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&1_000_000, &1_000);

        let user = Address::generate(&env);
        client.deposit(&user, &1);
    }
}
