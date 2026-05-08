//! VULNERABLE: Unprotected Emergency Withdraw
//!
//! A time-locked vault with an `emergency_withdraw` function intended for
//! admin use only. Because it never calls `admin.require_auth()`, any user
//! can invoke it to bypass the time-lock and drain funds immediately.
//!
//! VULNERABILITY: `emergency_withdraw` performs no admin auth check, so any
//! caller can release any user's locked balance before the lock expires.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
    UnlockLedger(Address),
}

pub(crate) fn get_balance(env: &Env, user: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(user.clone()))
        .unwrap_or(0)
}

pub(crate) fn set_balance(env: &Env, user: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(user.clone()), &amount);
}

#[contract]
pub struct TimeLockVault;

#[contractimpl]
impl TimeLockVault {
    /// Initialise the vault with an admin. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Deposit `amount` locked until `unlock_ledger`. Requires user auth.
    pub fn deposit(env: Env, user: Address, amount: i128, unlock_ledger: u32) {
        user.require_auth();
        let new_bal = get_balance(&env, &user) + amount;
        set_balance(&env, &user, new_bal);
        env.storage()
            .persistent()
            .set(&DataKey::UnlockLedger(user), &unlock_ledger);
    }

    /// Normal withdraw — only callable after the lock ledger has passed. Requires user auth.
    pub fn withdraw(env: Env, user: Address) {
        user.require_auth();
        let unlock: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::UnlockLedger(user.clone()))
            .unwrap_or(0);
        if env.ledger().sequence() < unlock {
            panic!("still locked");
        }
        set_balance(&env, &user, 0);
        env.storage()
            .persistent()
            .remove(&DataKey::UnlockLedger(user));
    }

    /// VULNERABLE: intended for admin only, but missing `admin.require_auth()`.
    /// Any caller can drain any user's balance before the lock expires.
    pub fn emergency_withdraw(env: Env, user: Address) {
        // ❌ Missing:
        //   let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        //   admin.require_auth();
        set_balance(&env, &user, 0);
        env.storage()
            .persistent()
            .remove(&DataKey::UnlockLedger(user));
    }

    /// Returns the current balance of `user`, defaulting to 0.
    pub fn balance(env: Env, user: Address) -> i128 {
        get_balance(&env, &user)
    }

    /// Returns the stored admin address.
    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (TimeLockVaultClient, Address, Address) {
        let id = env.register_contract(None, TimeLockVault);
        let client = TimeLockVaultClient::new(env, &id);
        let admin = Address::generate(env);
        let user = Address::generate(env);
        env.mock_all_auths();
        client.initialize(&admin);
        (client, admin, user)
    }

    #[test]
    fn test_admin_can_emergency_withdraw() {
        let env = Env::default();
        let (client, _admin, user) = setup(&env);

        env.mock_all_auths();
        client.deposit(&user, &1000, &9_999_999);
        assert_eq!(client.balance(&user), 1000);

        // Admin (mock auth) calls emergency_withdraw
        client.emergency_withdraw(&user);
        assert_eq!(client.balance(&user), 0);
    }

    /// Demonstrates the vulnerability: any user can call emergency_withdraw
    /// without being the admin, bypassing the time-lock entirely.
    #[test]
    fn test_anyone_can_emergency_withdraw_bypassing_lock() {
        let env = Env::default();
        let (client, _admin, user) = setup(&env);

        env.mock_all_auths();
        client.deposit(&user, &1000, &9_999_999);
        assert_eq!(client.balance(&user), 1000);

        // ❌ No auth mocked — contract never checks, so this succeeds for anyone.
        client.emergency_withdraw(&user);
        assert_eq!(client.balance(&user), 0);
    }

    #[test]
    #[should_panic(expected = "still locked")]
    fn test_normal_withdraw_respects_lock() {
        let env = Env::default();
        let (client, _admin, user) = setup(&env);
        env.mock_all_auths();
        client.deposit(&user, &1000, &9_999_999);
        client.withdraw(&user); // should panic — lock not expired
    }

    // ---- secure mirror tests -----------------------------------------------

    #[test]
    fn test_secure_admin_can_emergency_withdraw() {
        use crate::secure::SecureTimeLockVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureTimeLockVault);
        let client = SecureTimeLockVaultClient::new(&env, &id);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.deposit(&user, &1000, &9_999_999);
        assert_eq!(client.balance(&user), 1000);

        // Admin auth is satisfied by mock_all_auths
        client.emergency_withdraw(&user);
        assert_eq!(client.balance(&user), 0);
    }

    /// Non-admin call to emergency_withdraw must be rejected.
    #[test]
    #[should_panic]
    fn test_secure_non_admin_cannot_emergency_withdraw() {
        use crate::secure::SecureTimeLockVaultClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureTimeLockVault);
        let client = SecureTimeLockVaultClient::new(&env, &id);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.deposit(&user, &1000, &9_999_999);

        // Clear all mocked auths — admin.require_auth() must now fail.
        env.set_auths(&[]);
        client.emergency_withdraw(&user); // ✅ should panic
    }
}
