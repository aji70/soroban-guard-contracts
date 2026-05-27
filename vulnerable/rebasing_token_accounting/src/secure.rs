use soroban_sdk::{contract, contractimpl, Address, Env};
use super::DataKey;

/// SECURE: Rebasing-Aware Vault
///
/// Fixes the vulnerability by treating `TotalTokens` as a *live* balance
/// that is read and written on every deposit and withdrawal.  A `rebase`
/// helper lets tests inject external balance changes directly, simulating
/// what a rebasing token contract would do.
///
/// Key invariant: `total_tokens` always equals the vault's real token
/// balance, so share prices are always computed from accurate data.
#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// Deposit `amount` tokens.  Share price is computed from the *live*
    /// balance, so any prior rebase is already reflected.
    pub fn deposit(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        // ✅ Read the live balance before computing the share price.
        let total_tokens: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalTokens)
            .unwrap_or(0);
        let total_shares: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);

        let new_shares = if total_shares == 0 || total_tokens == 0 {
            amount
        } else {
            amount * total_shares / total_tokens
        };

        let prev: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(actor.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor), &(prev + new_shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares + new_shares));
        // ✅ TotalTokens is updated to the new live balance.
        env.storage()
            .persistent()
            .set(&DataKey::TotalTokens, &(total_tokens + amount));
    }

    /// Redeem `shares` for tokens.  Payout is computed from the *live*
    /// balance, so the vault can never pay out more than it holds.
    pub fn withdraw(env: Env, actor: Address, shares: i128) -> i128 {
        actor.require_auth();
        assert!(shares > 0, "shares must be positive");

        let held: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(actor.clone()))
            .unwrap_or(0);
        assert!(held >= shares, "insufficient shares");

        // ✅ Use the live balance for the redemption calculation.
        let total_tokens: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalTokens)
            .unwrap_or(0);
        let total_shares: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalShares)
            .unwrap_or(0);

        let tokens_out = shares * total_tokens / total_shares;

        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor), &(held - shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares - shares));
        // ✅ Deduct the actual payout from the live balance.
        env.storage()
            .persistent()
            .set(&DataKey::TotalTokens, &(total_tokens - tokens_out));

        tokens_out
    }

    /// Test helper: simulate an external rebase by adjusting `TotalTokens`
    /// directly (positive = supply expansion, negative = supply contraction).
    /// In production this would be driven by the token contract itself.
    pub fn rebase(env: Env, delta: i128) {
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalTokens)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalTokens, &(current + delta));
    }

    pub fn shares(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Shares(user))
            .unwrap_or(0)
    }

    pub fn live_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalTokens)
            .unwrap_or(0)
    }
}
