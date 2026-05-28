//! VULNERABLE: Cross-Contract Callback Trusts Invoker as Original User
//!
//! A vault contract grants privileged access (withdrawal) based on whoever
//! is the immediate caller of the function. A malicious intermediary contract
//! can call `withdraw` on behalf of a victim — the vault sees the intermediary
//! as the "user" and grants it the victim's balance.
//!
//! VULNERABILITY: `withdraw` uses `env.current_contract_address()` / the
//! passed `actor` without requiring that actor to sign the call. Any contract
//! can pass an arbitrary address as `actor` and drain that address's balance.
//!
//! SECURE MIRROR: `secure::SecureVault` calls `user.require_auth()` so only
//! a genuine signature from the user authorises a withdrawal.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Deposit `amount` for `user`. Requires user auth.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// VULNERABLE: accepts `actor` as the user without requiring their auth.
    ///
    /// # Vulnerability
    /// Missing `actor.require_auth()`. Any caller — including a malicious
    /// intermediary contract — can pass a victim's address as `actor` and
    /// withdraw their funds.
    pub fn withdraw(env: Env, actor: Address, amount: i128) -> i128 {
        // ❌ Missing: actor.require_auth();

        let key = DataKey::Balance(actor.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_bal = bal.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_bal);
        amount
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Simulated malicious intermediary contract
// ---------------------------------------------------------------------------

#[contract]
pub struct MaliciousIntermediary;

#[contractimpl]
impl MaliciousIntermediary {
    /// Calls the vulnerable vault's `withdraw` on behalf of `victim`,
    /// routing funds to the attacker without any victim signature.
    pub fn steal(
        env: Env,
        vault_id: Address,
        victim: Address,
        amount: i128,
    ) -> i128 {
        let client = VulnerableVaultClient::new(&env, &vault_id);
        // No victim auth — the vault doesn't check.
        client.withdraw(&victim, &amount)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_vault() -> (Env, Address, VulnerableVaultClient<'static>) {
        let env = Env::default();
        let vault_id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &vault_id);
        (env, vault_id, client)
    }

    /// Vulnerable path: malicious intermediary drains victim without their auth.
    #[test]
    fn test_vulnerable_intermediary_drains_victim() {
        let (env, vault_id, vault) = setup_vault();
        env.mock_all_auths();

        let victim = Address::generate(&env);
        vault.deposit(&victim, &1000);
        assert_eq!(vault.balance(&victim), 1000);

        // Register and call the malicious intermediary — no victim auth needed.
        let intermediary_id = env.register_contract(None, MaliciousIntermediary);
        let attacker_client = MaliciousIntermediaryClient::new(&env, &intermediary_id);

        let stolen = attacker_client.steal(&vault_id, &victim, &1000);
        assert_eq!(stolen, 1000);
        assert_eq!(vault.balance(&victim), 0, "victim funds drained");
    }

    /// Boundary: calling withdraw directly without auth also succeeds in the vulnerable version.
    #[test]
    fn test_vulnerable_direct_withdraw_no_auth_succeeds() {
        let (env, _vault_id, vault) = setup_vault();
        env.mock_all_auths();

        let victim = Address::generate(&env);
        vault.deposit(&victim, &500);

        // Clear auths — no signature from victim.
        env.set_auths(&[]);
        // Vulnerable: still succeeds.
        let out = vault.withdraw(&victim, &500);
        assert_eq!(out, 500);
        assert_eq!(vault.balance(&victim), 0);
    }

    /// Secure path: withdraw without victim auth must be rejected.
    #[test]
    fn test_secure_rejects_withdraw_without_user_auth() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        env.mock_all_auths();

        let victim = Address::generate(&env);
        client.deposit(&victim, &1000);

        // Attempt withdraw with no auth for victim.
        env.set_auths(&[]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.withdraw(&victim, &1000);
        }));
        assert!(result.is_err(), "secure vault must reject without user auth");
        assert_eq!(client.balance(&victim), 1000, "funds must remain intact");
    }

    /// Secure path: withdraw with proper user auth succeeds.
    #[test]
    fn test_secure_withdraw_with_auth_succeeds() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        env.mock_all_auths();

        let user = Address::generate(&env);
        client.deposit(&user, &1000);
        let out = client.withdraw(&user, &1000);
        assert_eq!(out, 1000);
        assert_eq!(client.balance(&user), 0);
    }
}
