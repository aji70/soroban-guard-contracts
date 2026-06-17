//! VULNERABLE: Empty Vault Share Inflation
//!
//! The first depositor mints shares 1:1 from `amount` with no virtual liquidity
//! or minimum initial deposit. An attacker seeds the vault with 1 unit, then
//! donates a large amount directly, inflating the share price so that a victim
//! depositing a normal amount receives 0 shares (integer division floors to 0).
//!
//! VULNERABILITY: `shares = amount * total_shares / total_assets` with no
//! virtual offset — first depositor controls the initial exchange rate.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

#[contracttype]
pub enum DataKey {
    TotalShares,
    TotalAssets,
    Shares(Address),
}

fn total_shares(env: &Env) -> i128 {
    env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(0)
}

fn total_assets(env: &Env) -> i128 {
    env.storage().persistent().get(&DataKey::TotalAssets).unwrap_or(0)
}

fn shares_of(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Shares(user.clone()))
        .unwrap_or(0)
}

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// VULNERABLE: first deposit sets share price with any amount, including 1.
    /// Subsequent depositors receive shares = amount * total_shares / total_assets,
    /// which floors to 0 when total_assets has been inflated by a donation.
    ///
    /// # Vulnerability
    /// No virtual liquidity offset and no minimum first deposit.
    pub fn deposit(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let ts = total_shares(&env);
        let ta = total_assets(&env);

        // ❌ BUG: first depositor mints shares == amount, setting the price.
        //    After a donation inflates ta, new shares floor to 0.
        let new_shares = if ts == 0 {
            amount
        } else {
            amount * ts / ta
        };

        assert!(new_shares > 0, "zero shares minted");

        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(ts + new_shares));
        env.storage()
            .persistent()
            .set(&DataKey::TotalAssets, &(ta + amount));
        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor), &(shares_of(&env, &actor) + new_shares));
    }

    /// Donate assets directly — simulates an unsolicited token transfer that
    /// inflates total_assets without minting shares.
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

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureVaultClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_vuln(env: &Env) -> VulnerableVaultClient {
        let id = env.register_contract(None, VulnerableVault);
        VulnerableVaultClient::new(env, &id)
    }

    fn setup_secure(env: &Env) -> SecureVaultClient {
        let id = env.register_contract(None, secure::SecureVault);
        SecureVaultClient::new(env, &id)
    }

    /// Demonstrates the vulnerable path: attacker seeds with 1, donates 1_000_000,
    /// victim deposits 500_000 but receives 0 shares.
    #[test]
    #[should_panic(expected = "zero shares minted")]
    fn test_share_inflation_victim_gets_zero_shares() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let attacker = Address::generate(&env);
        let victim = Address::generate(&env);

        // Attacker seeds vault with 1 unit → 1 share, price = 1:1
        client.deposit(&attacker, &1);
        assert_eq!(client.shares_of(&attacker), 1);

        // Attacker donates 1_000_000 directly → total_assets = 1_000_001, total_shares = 1
        client.donate(&1_000_000);

        // Victim deposits 500_000 → shares = 500_000 * 1 / 1_000_001 = 0 → panic
        client.deposit(&victim, &500_000);
    }

    /// Boundary: the attacker's own 1-unit seed deposit succeeds (unsafe state).
    #[test]
    fn test_attacker_seed_deposit_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let attacker = Address::generate(&env);
        client.deposit(&attacker, &1);
        assert_eq!(client.shares_of(&attacker), 1);
        assert_eq!(client.total_assets(), 1);
    }

    /// Secure vault: victim receives fair shares after attacker's donation attempt.
    #[test]
    fn test_secure_victim_receives_fair_shares() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_secure(&env);

        let attacker = Address::generate(&env);
        let victim = Address::generate(&env);

        // Attacker seeds with 1 unit — secure vault adds virtual offset
        client.deposit(&attacker, &1);

        // Attacker donates 1_000_000
        client.donate(&1_000_000);

        // Victim deposits 500_000 — virtual offset neutralises inflation
        client.deposit(&victim, &500_000);
        let victim_shares = client.shares_of(&victim);
        assert!(victim_shares > 0, "victim must receive shares");
    }
}
