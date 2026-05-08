//! VULNERABLE: Fee-on-Transfer Accounting
//!
//! A vault that credits users based on the `amount` parameter rather than the
//! tokens actually received. When a fee-on-transfer token is used, the token
//! contract deducts a fee during `transfer`, so the vault receives less than
//! `amount`. The vault still credits the full `amount`, creating an
//! uncollateralised internal balance that can be exploited to drain the pool.
//!
//! VULNERABILITY: `deposit` credits `amount` instead of
//! `post_balance - pre_balance` (the balance-delta pattern).
//!
//! SECURE MIRROR: `secure::SecureVault` snapshots the contract's token balance
//! before and after the transfer and credits only the delta.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Token interface (cross-contract) ─────────────────────────────────────────

pub mod token {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "TokenClient")]
    pub trait Token {
        fn transfer(env: Env, from: Address, to: Address, amount: i128);
        fn balance(env: Env, id: Address) -> i128;
    }
}

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Token,
}

// ── Vulnerable vault ──────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    pub fn initialize(env: Env, token: Address) {
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// VULNERABLE: credits `amount` regardless of how many tokens were
    /// actually received after the token's transfer fee.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);

        // ❌ Transfer first, then credit the parameter — not the delta.
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        // ❌ Credits `amount`, not what was actually received.
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}

// ── Mock fee token (10% fee on every transfer) ────────────────────────────────

#[contracttype]
pub enum TokenKey {
    Balance(Address),
}

#[contract]
pub struct FeeToken;

#[contractimpl]
impl FeeToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = TokenKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Deducts 10% as a fee; recipient receives only 90% of `amount`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let received = amount * 90 / 100; // 10% fee burned

        let from_key = TokenKey::Balance(from.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");
        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));

        let to_key = TokenKey::Balance(to.clone());
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&to_key, &(to_bal + received));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TokenKey::Balance(id))
            .unwrap_or(0)
    }
}

// ── Standard token (0% fee) ───────────────────────────────────────────────────

#[contract]
pub struct StandardToken;

#[contractimpl]
impl StandardToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = TokenKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let from_key = TokenKey::Balance(from.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");
        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));

        let to_key = TokenKey::Balance(to.clone());
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&to_key, &(to_bal + amount));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TokenKey::Balance(id))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};
    use secure::SecureVaultClient;

    // ── Exploit simulation: bug exists ────────────────────────────────────────

    /// Demonstrates the vulnerability: depositing 100 tokens via a 10%-fee
    /// token causes the vault to credit 100 even though it only received 90.
    #[test]
    fn test_exploit_vulnerable_vault_overcredits() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, FeeToken);
        let vault_id = env.register_contract(None, VulnerableVault);

        let token_client = FeeTokenClient::new(&env, &token_id);
        let vault_client = VulnerableVaultClient::new(&env, &vault_id);

        vault_client.initialize(&token_id);

        let user = Address::generate(&env);
        token_client.mint(&user, &100);

        vault_client.deposit(&user, &100);

        // Vault received only 90 (10% fee), but credited 100 — BUG.
        let vault_token_balance = token_client.balance(&vault_id);
        let user_vault_balance = vault_client.balance(&user);

        assert_eq!(vault_token_balance, 90, "vault actually holds 90 tokens");
        assert!(
            user_vault_balance > vault_token_balance,
            "exploit: internal credit ({user_vault_balance}) exceeds actual holdings ({vault_token_balance})"
        );
        assert_eq!(user_vault_balance, 100, "vulnerable vault overcredits to 100");
    }

    // ── Fix verification: secure vault credits only actual received ───────────

    /// After the fix, a 100-token deposit with a 10% fee credits only 90.
    #[test]
    fn test_fix_secure_vault_credits_actual_received() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, FeeToken);
        let vault_id = env.register_contract(None, secure::SecureVault);

        let token_client = FeeTokenClient::new(&env, &token_id);
        let vault_client = SecureVaultClient::new(&env, &vault_id);

        vault_client.initialize(&token_id);

        let user = Address::generate(&env);
        token_client.mint(&user, &100);

        vault_client.deposit(&user, &100);

        // Vault received 90 and credited exactly 90 — FIXED.
        assert_eq!(vault_client.balance(&user), 90);
        assert_eq!(token_client.balance(&vault_id), 90);
    }

    // ── Regression: standard token still credits exactly 100 ─────────────────

    /// Standard (0% fee) token: secure vault credits the full 100.
    #[test]
    fn test_regression_standard_token_credits_full_amount() {
        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, StandardToken);
        let vault_id = env.register_contract(None, secure::SecureVault);

        let token_client = StandardTokenClient::new(&env, &token_id);
        let vault_client = SecureVaultClient::new(&env, &vault_id);

        vault_client.initialize(&token_id);

        let user = Address::generate(&env);
        token_client.mint(&user, &100);

        vault_client.deposit(&user, &100);

        assert_eq!(vault_client.balance(&user), 100);
        assert_eq!(token_client.balance(&vault_id), 100);
    }
}
