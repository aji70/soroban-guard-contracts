//! VULNERABLE: Rebasing-Token Accounting
//!
//! A vault that tracks depositor shares using a fixed token-per-share ratio
//! recorded at deposit time.  The vault assumes the underlying token balance
//! can only change through its own `deposit` / `withdraw` entry-points.
//!
//! VULNERABILITY: Rebasing tokens can increase or decrease the vault's token
//! balance externally (outside any vault call).  Because the vault never
//! re-reads the real balance, the stored `total_tokens` drifts from reality:
//!
//! * Positive rebase → each share is worth more tokens than the vault thinks;
//!   early redeemers drain the surplus, late redeemers get less than they
//!   deposited.
//! * Negative rebase → the vault believes it holds more tokens than it does;
//!   withdrawals will eventually panic (underflow) or silently short-change
//!   depositors.
//!
//! SECURE MIRROR: `secure::SecureVault` re-reads the live token balance on
//! every deposit and withdrawal, keeping `total_tokens` in sync.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Shares held by a depositor.
    Shares(Address),
    /// Vault's cached total token balance (NOT re-read from the token).
    TotalTokens,
    /// Total shares outstanding.
    TotalShares,
}

// ---------------------------------------------------------------------------
// Vulnerable vault
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Deposit `amount` tokens.  Mints shares proportional to the *cached*
    /// `total_tokens`, which may already be stale after a rebase.
    ///
    /// BUG: vault accounting is not rebasing-aware.
    /// The fixture makes this unsafe path reachable and easy to scan.
    pub fn deposit(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

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

        // ❌ Share price is computed from the stale cached balance, not the
        //    live token balance.  A rebase before this call silently misprices
        //    the new shares.
        let new_shares = if total_shares == 0 || total_tokens == 0 {
            amount // 1:1 bootstrap
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
        // ❌ Only adds `amount`; never reconciles with the real balance.
        env.storage()
            .persistent()
            .set(&DataKey::TotalTokens, &(total_tokens + amount));
    }

    /// Redeem `shares` for tokens.  Token amount is computed from the *cached*
    /// `total_tokens`, which diverges from reality after any rebase.
    pub fn withdraw(env: Env, actor: Address, shares: i128) -> i128 {
        actor.require_auth();
        assert!(shares > 0, "shares must be positive");

        let held: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Shares(actor.clone()))
            .unwrap_or(0);
        assert!(held >= shares, "insufficient shares");

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

        // ❌ Redemption value uses the stale cached balance.
        let tokens_out = shares * total_tokens / total_shares;

        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor), &(held - shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(total_shares - shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalTokens, &(total_tokens - tokens_out));

        tokens_out
    }

    /// Simulate an external rebase: directly adjusts the vault's *real*
    /// token balance without updating `TotalTokens`.  In production this
    /// would be the token contract rebasing all holder balances.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        // BUG: vault accounting is not rebasing-aware.
        // The fixture makes this unsafe path reachable and easy to scan.
        let _ = (actor, amount);
        // The real balance has changed externally; TotalTokens is now stale.
        // Nothing here reconciles the two — that is the vulnerability.
        let _ = env;
    }

    pub fn shares(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Shares(user))
            .unwrap_or(0)
    }

    pub fn total_tokens(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalTokens)
            .unwrap_or(0)
    }

    pub fn total_shares(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalShares)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    // -----------------------------------------------------------------------
    // Baseline: normal deposit + withdraw round-trips correctly.
    // -----------------------------------------------------------------------
    #[test]
    fn test_normal_roundtrip() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &id);
        let alice = Address::generate(&env);

        client.deposit(&alice, &1000);
        assert_eq!(client.shares(&alice), 1000);

        let out = client.withdraw(&alice, &1000);
        assert_eq!(out, 1000);
        assert_eq!(client.shares(&alice), 0);
    }

    // -----------------------------------------------------------------------
    // DEMONSTRATES VULNERABILITY — positive rebase misprices redemptions.
    //
    // Scenario:
    //   1. Alice deposits 1 000 tokens → 1 000 shares, cached total = 1 000.
    //   2. Token contract rebases +500 (vault now holds 1 500 real tokens).
    //      The vault's cached TotalTokens is still 1 000.
    //   3. Bob deposits 1 000 tokens.
    //      Share price = cached 1 000 / 1 000 shares = 1.0, so Bob gets 1 000
    //      shares — but the real price should be 1 500/1 000 = 1.5, meaning
    //      Bob should only get ~667 shares.
    //   4. Alice redeems her 1 000 shares.
    //      Cached total = 2 000, total shares = 2 000 → 1 000 tokens out.
    //      Alice loses her 500-token rebase gain; Bob effectively captured it.
    // -----------------------------------------------------------------------
    #[test]
    fn test_positive_rebase_misprices_shares() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &id);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        // Step 1: Alice deposits.
        client.deposit(&alice, &1_000);
        assert_eq!(client.total_tokens(), 1_000);
        assert_eq!(client.total_shares(), 1_000);

        // Step 2: Positive rebase — vault's real balance grows by 500, but
        // TotalTokens is NOT updated (simulates external rebase).
        // We call vulnerable_entry to mark the unsafe path; the cached value
        // stays at 1 000 while the real balance is now 1 500.
        client.vulnerable_entry(&alice, &500);
        // Cached total is still 1 000 — the bug.
        assert_eq!(client.total_tokens(), 1_000);

        // Step 3: Bob deposits 1 000 at the stale price.
        client.deposit(&bob, &1_000);
        // Bob gets 1 000 shares (1:1) instead of the correct ~667.
        assert_eq!(client.shares(&bob), 1_000);

        // Step 4: Alice redeems — she gets only 1 000 tokens back, not 1 500.
        let alice_out = client.withdraw(&alice, &1_000);
        // Alice should have received 1 500 (her 1 000 + 500 rebase gain),
        // but the stale accounting gives her only 1 000.
        assert!(
            alice_out < 1_500,
            "vulnerable: Alice received {} but should have gotten 1500 after rebase",
            alice_out
        );
        // The 500-token rebase gain is silently lost from Alice's perspective.
        assert_eq!(alice_out, 1_000);
    }

    // -----------------------------------------------------------------------
    // DEMONSTRATES VULNERABILITY — negative rebase causes insolvency.
    //
    // Scenario:
    //   1. Alice deposits 1 000 tokens → 1 000 shares, cached total = 1 000.
    //   2. Token contract rebases −400 (vault now holds 600 real tokens).
    //      Cached TotalTokens stays at 1 000.
    //   3. Alice redeems 1 000 shares → vault computes 1 000 tokens out,
    //      but only 600 exist.  The vault is insolvent.
    // -----------------------------------------------------------------------
    #[test]
    fn test_negative_rebase_causes_insolvency() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &id);
        let alice = Address::generate(&env);

        client.deposit(&alice, &1_000);

        // Negative rebase: real balance drops to 600, cache stays at 1 000.
        client.vulnerable_entry(&alice, &-400);
        assert_eq!(client.total_tokens(), 1_000); // stale — should be 600

        // Alice redeems; vault believes it can pay 1 000 but only has 600.
        let out = client.withdraw(&alice, &1_000);
        // The vault "pays" 1 000 from its stale accounting — it is insolvent.
        assert_eq!(out, 1_000);
        // TotalTokens goes negative, confirming the insolvency.
        assert!(
            client.total_tokens() < 0,
            "vault is insolvent: TotalTokens = {}",
            client.total_tokens()
        );
    }

    // -----------------------------------------------------------------------
    // Secure version — positive rebase: share price is recalculated from the
    // live balance, so Alice's gain is preserved and Bob pays the correct price.
    // -----------------------------------------------------------------------
    #[test]
    fn test_secure_positive_rebase_preserves_invariant() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        // Alice deposits 1 000.
        client.deposit(&alice, &1_000);

        // Positive rebase: inject 500 directly into the live balance.
        client.rebase(&500);
        assert_eq!(client.live_balance(), 1_500);

        // Bob deposits 1 000 at the correct live price (1 500 tokens / 1 000
        // shares = 1.5 tokens/share → Bob gets floor(1000*1000/1500) = 666 shares).
        client.deposit(&bob, &1_000);
        let bob_shares = client.shares(&bob);
        assert!(
            bob_shares < 1_000,
            "secure: Bob should get fewer shares after positive rebase, got {}",
            bob_shares
        );

        // Alice redeems her 1 000 shares; she should receive more than 1 000
        // tokens because the rebase increased the share price.
        let alice_out = client.withdraw(&alice, &1_000);
        assert!(
            alice_out > 1_000,
            "secure: Alice should profit from rebase, got {}",
            alice_out
        );
    }

    // -----------------------------------------------------------------------
    // Secure version — negative rebase: vault stays solvent because it reads
    // the live balance and refuses to over-pay.
    // -----------------------------------------------------------------------
    #[test]
    fn test_secure_negative_rebase_stays_solvent() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.deposit(&alice, &1_000);

        // Negative rebase: live balance drops to 600.
        client.rebase(&-400);
        assert_eq!(client.live_balance(), 600);

        // Alice redeems; secure vault pays based on live balance (600 tokens).
        let out = client.withdraw(&alice, &1_000);
        assert_eq!(out, 600);
        // Vault is solvent: live balance is exactly 0 after full redemption.
        assert_eq!(client.live_balance(), 0);
    }
}
