//! VULNERABLE: Rescue Function Can Drain Primary Protocol Asset
//!
//! A vault contract that accepts deposits of a primary token and provides a
//! `rescue_token()` function intended to recover accidentally sent tokens.
//! However, the rescue function does not validate that the token being rescued
//! is different from the managed primary asset.
//!
//! VULNERABILITY: `rescue_token` accepts any token address, including the
//! managed token. Admin can drain all user deposits via the rescue path,
//! breaking accounting and enabling a complete rug-pull.
//!
//! SECURE MIRROR: `secure::SecureVault` explicitly blocks rescue of the
//! managed token, ensuring the rescue function can only recover unrelated assets.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    ManagedToken,
    Balance(Address),
}

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Initialize the vault with an admin and the primary managed token.
    pub fn initialize(env: Env, admin: Address, managed_token: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ManagedToken, &managed_token);
    }

    /// Deposit `amount` of the managed token into the vault for `user`.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let managed_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .expect("not initialized");

        let token_client = token::Client::new(&env, &managed_token);
        token_client.transfer(&user, &env.current_contract_address(), &amount);

        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Withdraw `amount` of the managed token from the vault for `user`.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);

        let managed_token: Address = env
            .storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .unwrap();

        let token_client = token::Client::new(&env, &managed_token);
        token_client.transfer(&env.current_contract_address(), &user, &amount);
    }

    /// VULNERABLE: rescue any token, including the managed token.
    /// Intended for recovering accidentally sent tokens, but does not block
    /// the primary asset. Admin can drain all user deposits.
    ///
    /// # Vulnerability
    /// Missing check: `token != managed_token`. Impact: admin can rug-pull
    /// the entire protocol balance, breaking accounting and user trust.
    pub fn rescue_token(env: Env, token: Address, recipient: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        // ❌ Missing: check that token != managed_token
        // Admin can drain the primary asset users deposited

        let token_client = token::Client::new(&env, &token);
        token_client.transfer(&env.current_contract_address(), &recipient, &amount);
    }

    /// Returns the balance of `user` in the vault.
    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }

    /// Returns the managed token address.
    pub fn get_managed_token(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::ManagedToken)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        VulnerableVaultClient<'static>,
        Address,
        Address,
        token::StellarAssetClient<'static>,
    ) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let managed_token_admin = Address::generate(&env);
        let managed_token =
            token::StellarAssetClient::new(&env, &env.register_stellar_asset_contract_v2(managed_token_admin.clone()));

        let contract_id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &contract_id);

        client.initialize(&admin, &managed_token.address);

        (env, client, admin, managed_token_admin, managed_token)
    }

    /// Demonstrates the vulnerability: admin rescues the managed token, draining user deposits.
    #[test]
    fn test_admin_rescues_managed_token_drains_deposits() {
        let (env, client, admin, token_admin, managed_token) = setup();

        let user = Address::generate(&env);
        managed_token.mint(&user, &1000);

        client.deposit(&user, &1000);
        assert_eq!(client.get_balance(&user), 1000);

        let contract_balance = managed_token.balance(&env.current_contract_address());
        assert_eq!(contract_balance, 1000);

        // Admin calls rescue_token with the managed token address — no validation blocks this.
        let attacker_wallet = Address::generate(&env);
        client.rescue_token(&managed_token.address, &attacker_wallet, &1000);

        // User's accounting balance is still 1000, but actual tokens are gone.
        assert_eq!(client.get_balance(&user), 1000, "accounting unchanged");
        assert_eq!(
            managed_token.balance(&env.current_contract_address()),
            0,
            "contract drained"
        );
        assert_eq!(
            managed_token.balance(&attacker_wallet),
            1000,
            "attacker received funds"
        );
    }

    /// Admin can rescue unrelated tokens without issue (intended behavior).
    #[test]
    fn test_admin_rescues_unrelated_token_works() {
        let (env, client, admin, _token_admin, managed_token) = setup();

        let unrelated_token_admin = Address::generate(&env);
        let unrelated_token = token::StellarAssetClient::new(
            &env,
            &env.register_stellar_asset_contract_v2(unrelated_token_admin.clone()),
        );

        unrelated_token.mint(&env.current_contract_address(), &500);

        let recipient = Address::generate(&env);
        client.rescue_token(&unrelated_token.address, &recipient, &500);

        assert_eq!(unrelated_token.balance(&recipient), 500);
        assert_eq!(unrelated_token.balance(&env.current_contract_address()), 0);
    }

    /// Secure version: rescue_token rejects the managed token.
    #[test]
    fn test_secure_rejects_rescue_of_managed_token() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let managed_token_admin = Address::generate(&env);
        let managed_token =
            token::StellarAssetClient::new(&env, &env.register_stellar_asset_contract_v2(managed_token_admin.clone()));

        let contract_id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        client.initialize(&admin, &managed_token.address);

        let user = Address::generate(&env);
        managed_token.mint(&user, &1000);
        client.deposit(&user, &1000);

        let attacker_wallet = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.rescue_token(&managed_token.address, &attacker_wallet, &1000);
        }));

        assert!(
            result.is_err(),
            "must reject rescue of managed token"
        );
        assert_eq!(client.get_balance(&user), 1000, "user balance intact");
        assert_eq!(
            managed_token.balance(&env.current_contract_address()),
            1000,
            "contract balance intact"
        );
    }
}
