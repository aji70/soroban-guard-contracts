#![no_std]
use super::{shares_of, total_assets, total_shares, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

/// Virtual offset applied to both assets and shares on first deposit.
/// This prevents the first depositor from setting an arbitrary share price.
const VIRTUAL_OFFSET: i128 = 1_000;

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// SECURE: uses virtual assets + virtual shares so the first depositor
    /// cannot manipulate the initial exchange rate.
    ///
    /// shares_minted = amount * (total_shares + VIRTUAL_OFFSET)
    ///                        / (total_assets + VIRTUAL_OFFSET)
    pub fn deposit(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let ts = total_shares(&env);
        let ta = total_assets(&env);

        // ✅ Virtual offset prevents share-price manipulation on empty vault.
        let new_shares = amount * (ts + VIRTUAL_OFFSET) / (ta + VIRTUAL_OFFSET);
        assert!(new_shares > 0, "zero shares minted");

        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(ts + new_shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(ta + amount));
        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor.clone()), &(shares_of(&env, &actor) + new_shares));
    }

    /// Donate assets — simulates unsolicited transfer.
    pub fn donate(env: Env, amount: i128) {
        assert!(amount > 0);
        let ta = total_assets(&env);
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(ta + amount));
    }

    pub fn shares_of(env: Env, user: Address) -> i128 {
        shares_of(&env, &user)
    }

    pub fn total_shares(env: Env) -> i128 {
        total_shares(&env)
    }

    pub fn total_assets(env: Env) -> i128 {
        total_assets(&env)
    }
}
