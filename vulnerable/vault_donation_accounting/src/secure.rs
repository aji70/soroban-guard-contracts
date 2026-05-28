#![no_std]
use super::{shares_of, total_shares, DataKey};
use soroban_sdk::{contract, contractimpl, Address, Env};

/// Internal managed assets — only updated through deposit/withdraw, never by donate.
const MANAGED_ASSETS_KEY: &str = "ManagedAssets";

fn managed_assets(env: &Env) -> i128 {
    env.storage()
        .persistent()
        .get(&soroban_sdk::Symbol::new(env, MANAGED_ASSETS_KEY))
        .unwrap_or(0)
}

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// SECURE: uses an internal managed-assets counter instead of live balance.
    /// Donations do not affect share math.
    pub fn deposit(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let ts = total_shares(&env);
        // ✅ Reads managed counter — immune to external donations.
        let ta = managed_assets(&env);

        let new_shares = if ts == 0 { amount } else { amount * ts / ta };
        assert!(new_shares > 0, "zero shares minted");

        let key = soroban_sdk::Symbol::new(&env, MANAGED_ASSETS_KEY);
        env.storage().persistent().set(&key, &(ta + amount));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(ts + new_shares));
        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor.clone()), &(shares_of(&env, &actor) + new_shares));
    }

    /// Donate is accepted but does NOT update managed assets — share math is unaffected.
    pub fn donate(env: Env, amount: i128) {
        assert!(amount > 0);
        // ✅ Intentionally ignored for share accounting purposes.
        let _ = (env, amount);
    }

    pub fn shares_of(env: Env, user: Address) -> i128 {
        shares_of(&env, &user)
    }

    pub fn total_shares(env: Env) -> i128 {
        total_shares(&env)
    }

    pub fn managed_assets(env: Env) -> i128 {
        managed_assets(&env)
    }
}
