//! VULNERABLE: Untrusted Oracle Setter
//!
//! A governance function lets anyone store an arbitrary oracle address.
//! No allowlist or interface check is performed.  A malicious oracle can
//! return inflated prices, enabling over-collateralised borrows or
//! sandwich attacks against any contract that reads the stored oracle.
//!
//! VULNERABILITY: `set_oracle` stores the caller-supplied address without
//! verifying it against an approved registry.
//!
//! SEVERITY: Critical
//!
//! SECURE MIRROR: `secure::SecureOracleSetter` requires admin auth and
//! validates the oracle address against an on-chain allowlist.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Oracle,
    Allowlist,
}

#[contract]
pub struct UntrustedOracleSetter;

#[contractimpl]
impl UntrustedOracleSetter {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: stores any oracle address with no auth and no allowlist check.
    pub fn set_oracle(env: Env, oracle: Address) {
        // ❌ Missing: admin.require_auth()
        // ❌ Missing: assert oracle is on allowlist
        env.storage().persistent().set(&DataKey::Oracle, &oracle);
    }

    /// Read the price from whatever oracle address was stored.
    /// In a real contract this would cross-call the oracle; here we simulate
    /// by reading a price the oracle "reported" into shared storage.
    pub fn get_price(env: Env) -> i128 {
        let oracle: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Oracle)
            .expect("oracle not set");
        // Simulate reading from the oracle: in tests the oracle address is used
        // as a key to look up a price injected by the test harness.
        env.storage()
            .persistent()
            .get(&oracle)
            .unwrap_or(0)
    }

    /// Test helper: inject a price that `get_price` will return for `oracle`.
    pub fn mock_oracle_price(env: Env, oracle: Address, price: i128) {
        env.storage().persistent().set(&oracle, &price);
    }

    pub fn get_oracle(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Oracle)
            .expect("oracle not set")
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Add an address to the oracle allowlist (admin only, used by secure path).
    pub fn add_to_allowlist(env: Env, oracle: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        let mut list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Allowlist)
            .unwrap_or(Vec::new(&env));
        list.push_back(oracle);
        env.storage().persistent().set(&DataKey::Allowlist, &list);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (Address, UntrustedOracleSetterClient) {
        let id = env.register_contract(None, UntrustedOracleSetter);
        let client = UntrustedOracleSetterClient::new(env, &id);
        let admin = Address::generate(env);
        env.mock_all_auths();
        client.initialize(&admin);
        (admin, client)
    }

    /// DEMONSTRATES VULNERABILITY: malicious oracle returns inflated price.
    #[test]
    fn test_malicious_oracle_inflates_price() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        env.mock_all_auths();

        let malicious_oracle = Address::generate(&env);
        // Inject an inflated price for the malicious oracle.
        client.mock_oracle_price(&malicious_oracle, &999_999_999);

        // No auth required — attacker sets their oracle.
        client.set_oracle(&malicious_oracle);
        assert_eq!(client.get_oracle(), malicious_oracle);

        // Contract now reads the manipulated price.
        let price = client.get_price();
        assert_eq!(price, 999_999_999, "malicious oracle price accepted");
    }

    /// Boundary: any address is accepted, including one with no price data.
    #[test]
    fn test_arbitrary_address_accepted() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        env.mock_all_auths();

        let random = Address::generate(&env);
        client.set_oracle(&random);
        // No price injected — returns 0 (silent failure in a real contract).
        assert_eq!(client.get_price(), 0);
    }

    /// SECURE: non-allowlisted oracle is rejected.
    #[test]
    fn test_secure_rejects_non_allowlisted_oracle() {
        use crate::secure::SecureOracleSetterClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureOracleSetter);
        let client = SecureOracleSetterClient::new(&env, &id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let malicious = Address::generate(&env);
        let result = std::panic::catch_unwind(|| client.set_oracle(&malicious));
        assert!(result.is_err(), "non-allowlisted oracle must be rejected");
    }

    /// SECURE: allowlisted oracle is accepted.
    #[test]
    fn test_secure_accepts_allowlisted_oracle() {
        use crate::secure::SecureOracleSetterClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureOracleSetter);
        let client = SecureOracleSetterClient::new(&env, &id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let trusted = Address::generate(&env);
        client.add_to_allowlist(&trusted);
        client.set_oracle(&trusted);
        assert_eq!(client.get_oracle(), trusted);
    }
}
