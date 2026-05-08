//! VULNERABLE: Unprotected Pause
//!
//! A token contract where `pause()` and `unpause()` have no admin auth check.
//! Any attacker can freeze the contract indefinitely (griefing) or unpause a
//! contract the admin intentionally paused.
//!
//! VULNERABILITY: Missing `admin.require_auth()` in `pause()` and `unpause()`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Paused,
    Balance(Address),
}

#[contract]
pub struct UnprotectedPause;

#[contractimpl]
impl UnprotectedPause {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    /// ❌ No admin auth check — anyone can freeze the contract.
    pub fn pause(env: Env) {
        env.storage().persistent().set(&DataKey::Paused, &true);
    }

    /// ❌ No admin auth check — anyone can unpause a deliberately paused contract.
    pub fn unpause(env: Env) {
        env.storage().persistent().set(&DataKey::Paused, &false);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let paused: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false);
        if paused {
            panic!("contract is paused");
        }

        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to);
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage().persistent().set(&to_key, &(to_bal + amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, soroban_sdk::Address, UnprotectedPauseClient<'static>) {
        let env = Env::default();
        let contract_id = env.register_contract(None, UnprotectedPause);
        let client = UnprotectedPauseClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_admin_can_pause_and_unpause() {
        let (env, _admin, client) = setup();
        env.mock_all_auths();

        client.pause();
        assert!(client.is_paused());

        client.unpause();
        assert!(!client.is_paused());
    }

    /// Demonstrates the vulnerability: attacker pauses without any auth.
    #[test]
    fn test_attacker_can_pause_without_auth() {
        let (env, _admin, client) = setup();
        // No mock_all_auths — contract never checks auth, so this succeeds.
        let _ = &env; // env held to keep client alive
        client.pause();
        assert!(client.is_paused());
    }

    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_transfer_fails_when_paused() {
        let (env, _admin, client) = setup();

        let alice = Address::generate(&env);
        client.mint(&alice, &1000);

        // Attacker pauses — no auth needed (the vulnerability).
        client.pause();

        // Transfer should now fail.
        env.mock_all_auths();
        let bob = Address::generate(&env);
        client.transfer(&alice, &bob, &500);
    }
}
