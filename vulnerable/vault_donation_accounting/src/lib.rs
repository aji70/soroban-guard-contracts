//! VULNERABLE: Vault Donation Accounting
//!
//! The vault computes `total_assets` from a live balance field that any caller
//! can inflate via `donate()`. Because share minting uses this live value,
//! an unsolicited donation shifts the share price before the next depositor,
//! causing them to receive fewer shares than they should.
//!
//! VULNERABILITY: share math reads live token balance instead of a managed
//! internal counter that only changes through controlled deposit/withdraw paths.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    /// Live balance — writable by donate(), not just deposit().
    LiveBalance,
    TotalShares,
    Shares(Address),
}

pub(crate) fn live_balance(env: &Env) -> i128 {
    env.storage().persistent().get(&DataKey::LiveBalance).unwrap_or(0)
}

pub(crate) fn total_shares(env: &Env) -> i128 {
    env.storage().persistent().get(&DataKey::TotalShares).unwrap_or(0)
}

pub(crate) fn shares_of(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Shares(user.clone()))
        .unwrap_or(0)
}

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// VULNERABLE: uses `live_balance` (inflatable by donate) as total_assets.
    ///
    /// # Vulnerability
    /// A donation before this call inflates the denominator, reducing shares minted.
    pub fn deposit(env: Env, actor: Address, amount: i128) {
        actor.require_auth();
        assert!(amount > 0, "amount must be positive");

        let ts = total_shares(&env);
        // ❌ BUG: reads live balance — donations shift this value externally.
        let ta = live_balance(&env);

        let new_shares = if ts == 0 { amount } else { amount * ts / ta };
        assert!(new_shares > 0, "zero shares minted");

        env.storage()
            .persistent()
            .set(&DataKey::LiveBalance, &(ta + amount));
        env.storage()
            .persistent()
            .set(&DataKey::TotalShares, &(ts + new_shares));
        env.storage()
            .persistent()
            .set(&DataKey::Shares(actor), &(shares_of(&env, &actor) + new_shares));
    }

    /// Simulates an unsolicited token transfer — inflates live balance without
    /// minting shares, distorting the share price for the next depositor.
    pub fn donate(env: Env, amount: i128) {
        assert!(amount > 0);
        let bal = live_balance(&env);
        env.storage()
            .persistent()
            .set(&DataKey::LiveBalance, &(bal + amount));
    }

    pub fn shares_of(env: Env, user: Address) -> i128 {
        shares_of(&env, &user)
    }

    pub fn total_shares(env: Env) -> i128 {
        total_shares(&env)
    }

    pub fn total_assets(env: Env) -> i128 {
        live_balance(&env)
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

    /// Demonstrates the vulnerability: donation shifts share accounting.
    /// Alice deposits 1_000 → 1_000 shares. Attacker donates 9_000.
    /// Bob deposits 1_000 → should get ~1_000 shares but gets 100.
    #[test]
    fn test_donation_distorts_share_price() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.deposit(&alice, &1_000);
        assert_eq!(client.shares_of(&alice), 1_000);

        // Attacker donates 9_000 — live balance becomes 10_000, shares still 1_000
        client.donate(&9_000);

        // Bob deposits same 1_000 → shares = 1_000 * 1_000 / 10_000 = 100
        client.deposit(&bob, &1_000);
        let bob_shares = client.shares_of(&bob);

        // ❌ Bob receives far fewer shares than Alice for the same deposit
        assert!(bob_shares < client.shares_of(&alice), "donation distorted share price");
        assert_eq!(bob_shares, 100);
    }

    /// Boundary: donation alone (no prior deposit) leaves unsafe state.
    #[test]
    fn test_donation_before_any_deposit_inflates_balance() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_vuln(&env);

        client.donate(&1_000_000);
        assert_eq!(client.total_assets(), 1_000_000);
        assert_eq!(client.total_shares(), 0);
    }

    /// Secure vault: donation does NOT affect internal managed assets counter.
    #[test]
    fn test_secure_donation_does_not_shift_share_price() {
        let env = Env::default();
        env.mock_all_auths();
        let client = setup_secure(&env);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.deposit(&alice, &1_000);
        let alice_shares = client.shares_of(&alice);

        // Donate — secure vault ignores this for share math
        client.donate(&9_000);

        // Bob deposits same amount — should receive same shares as Alice
        client.deposit(&bob, &1_000);
        let bob_shares = client.shares_of(&bob);

        assert_eq!(alice_shares, bob_shares, "secure vault preserves share price");
    }
}
