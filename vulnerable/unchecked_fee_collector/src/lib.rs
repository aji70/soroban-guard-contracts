//! VULNERABLE: Unchecked Fee Collector
//!
//! A fee contract where `set_collector` stores any address as the fee
//! collector without requiring admin authorisation or validating that the
//! address is on an approved list.  Fees can be silently redirected to an
//! attacker-controlled address or to an address incapable of receiving tokens.
//!
//! VULNERABILITY: `set_collector` trusts the caller-supplied address with no
//! auth check and no allowlist validation.
//!
//! SECURE MIRROR: `secure::SecureFeeCollector` requires admin auth and
//! rejects collectors that are not on the approved list.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Vec};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Collector,
    Fees,
    Approved,
}

#[contract]
pub struct UncheckedFeeCollector;

#[contractimpl]
impl UncheckedFeeCollector {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
    }

    /// VULNERABLE: any caller can redirect fees to any address — no auth, no allowlist.
    pub fn set_collector(env: Env, collector: Address) {
        // ❌ Missing: admin.require_auth()
        // ❌ Missing: assert collector is on approved list
        env.storage().persistent().set(&DataKey::Collector, &collector);
    }

    /// Accumulate a flat fee from a notional operation.
    pub fn collect_fee(env: Env, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let fee = amount / 100; // 1 %
        let current: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &(current + fee));
        env.events().publish((symbol_short!("fee"),), fee);
    }

    /// Transfer accumulated fees to the stored collector.
    pub fn withdraw(env: Env) {
        let collector: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Collector)
            .expect("collector not set");
        let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
        env.events().publish((symbol_short!("withdraw"),), (collector, fees));
    }

    pub fn get_fees(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Fees).unwrap_or(0)
    }

    pub fn get_collector(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Collector)
            .expect("collector not set")
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Add an address to the approved-collector list (admin only, used by secure path).
    pub fn add_approved(env: Env, collector: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        let mut list: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Approved)
            .unwrap_or(Vec::new(&env));
        list.push_back(collector);
        env.storage().persistent().set(&DataKey::Approved, &list);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(env: &Env) -> (Address, UncheckedFeeCollectorClient) {
        let id = env.register_contract(None, UncheckedFeeCollector);
        let client = UncheckedFeeCollectorClient::new(env, &id);
        let admin = Address::generate(env);
        env.mock_all_auths();
        client.initialize(&admin);
        (admin, client)
    }

    /// DEMONSTRATES VULNERABILITY: attacker redirects collector without auth.
    #[test]
    fn test_attacker_redirects_collector() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        env.mock_all_auths();

        let attacker = Address::generate(&env);
        // No auth required — attacker sets themselves as collector.
        client.set_collector(&attacker);
        assert_eq!(client.get_collector(), attacker);

        client.collect_fee(&1000);
        assert_eq!(client.get_fees(), 10);

        // Fees now drain to the attacker.
        client.withdraw();
        assert_eq!(client.get_fees(), 0);
    }

    /// Boundary: collector can be set to any arbitrary address (zero-value risk).
    #[test]
    fn test_any_address_accepted_as_collector() {
        let env = Env::default();
        let (_admin, client) = setup(&env);
        env.mock_all_auths();

        let random = Address::generate(&env);
        client.set_collector(&random);
        assert_eq!(client.get_collector(), random);
    }

    /// SECURE: only admin can set collector, and only from the approved list.
    #[test]
    fn test_secure_rejects_unapproved_collector() {
        use crate::secure::SecureFeeCollectorClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureFeeCollector);
        let client = SecureFeeCollectorClient::new(&env, &id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let attacker = Address::generate(&env);
        // attacker is not on the approved list — must panic.
        let result = std::panic::catch_unwind(|| client.set_collector(&attacker));
        assert!(result.is_err(), "unapproved collector must be rejected");
    }

    /// SECURE: approved collector is accepted.
    #[test]
    fn test_secure_accepts_approved_collector() {
        use crate::secure::SecureFeeCollectorClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureFeeCollector);
        let client = SecureFeeCollectorClient::new(&env, &id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);

        let approved = Address::generate(&env);
        client.add_approved(&approved);
        client.set_collector(&approved);
        assert_eq!(client.get_collector(), approved);
    }
}
