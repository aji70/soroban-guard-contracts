//! VULNERABLE: Oracle Source Not Whitelisted
//!
//! A price consumer that accepts the oracle contract address from the caller
//! at call time.  Any address can be supplied — including a malicious contract
//! that returns an inflated price — because there is no allowlist check.
//!
//! VULNERABILITY: `update_price` trusts the caller-supplied `oracle` address
//! and stores whatever price it returns.  An attacker deploys a fake oracle
//! returning an arbitrary value and passes its address in, corrupting the
//! on-chain price used for valuations, liquidations, or swaps.
//!
//! SEVERITY: Critical

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Price,
    Admin,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct PriceConsumer;

#[contractimpl]
impl PriceConsumer {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: accepts a caller-supplied `oracle` address and stores the
    /// price it returns without verifying the address is trusted.
    ///
    /// ❌ BUG: attacker passes their own contract as `oracle`; the fake price
    /// is stored and used downstream as if it came from a legitimate feed.
    pub fn update_price(env: Env, actor: Address, oracle: Address, price: i128) {
        actor.require_auth();

        // ❌ oracle address is caller-supplied — no allowlist check performed
        let _ = oracle; // in a real contract this would be cross-contract called

        // Store the price as-is, trusting the caller-supplied source
        env.storage().instance().set(&DataKey::Price, &price);
    }

    pub fn get_price(env: Env) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Price)
            .unwrap_or(0)
    }
}

// ── Fake oracle (attacker-controlled) ────────────────────────────────────────

/// Simulates a malicious oracle contract deployed by an attacker.
/// Returns an inflated price regardless of market reality.
#[contract]
pub struct FakeOracle;

#[contractimpl]
impl FakeOracle {
    pub fn price(_env: Env) -> i128 {
        i128::MAX // attacker-controlled, wildly inflated
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, PriceConsumerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PriceConsumer);
        let client = PriceConsumerClient::new(&env, &id);
        let admin = Address::generate(&env);
        let actor = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, actor, client)
    }

    /// Legitimate oracle address with a fair price — accepted (expected).
    #[test]
    fn test_vulnerable_legitimate_oracle_accepted() {
        let (env, _admin, actor, client) = setup();
        let legit_oracle = Address::generate(&env);
        client.update_price(&actor, &legit_oracle, &1_000_i128);
        assert_eq!(client.get_price(), 1_000);
    }

    /// ❌ Attacker deploys a fake oracle and passes it as the oracle address.
    /// The vulnerable contract stores the attacker-supplied price without
    /// any source validation.
    #[test]
    fn test_vulnerable_fake_oracle_accepted() {
        let (env, _admin, actor, client) = setup();

        // Attacker registers their own fake oracle contract
        let fake_oracle_id = env.register_contract(None, FakeOracle);
        let fake_oracle = Address::from_contract_id(&fake_oracle_id);

        // ❌ VULNERABLE: fake oracle address is accepted; inflated price stored
        client.update_price(&actor, &fake_oracle, &i128::MAX);
        assert_eq!(client.get_price(), i128::MAX);
    }

    /// Boundary: any arbitrary address (even a random wallet) is accepted.
    #[test]
    fn test_vulnerable_random_address_accepted_as_oracle() {
        let (env, _admin, actor, client) = setup();
        let random = Address::generate(&env);
        // ❌ No check — random address passes as oracle source
        client.update_price(&actor, &random, &999_999_999_i128);
        assert_eq!(client.get_price(), 999_999_999);
    }

    // ── secure mirror ────────────────────────────────────────────────────────

    fn setup_secure() -> (Env, Address, Address, secure::SecurePriceConsumerClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecurePriceConsumer);
        let client = secure::SecurePriceConsumerClient::new(&env, &id);
        let admin = Address::generate(&env);
        let legit_oracle = Address::generate(&env);
        client.initialize(&admin, &legit_oracle);
        let actor = Address::generate(&env);
        (env, admin, actor, client)
    }

    /// ✅ Secure path accepts a price update only from the whitelisted oracle.
    #[test]
    fn test_secure_whitelisted_oracle_accepted() {
        let (env, _admin, actor, client) = setup_secure();
        // retrieve the stored oracle so we can pass it as caller
        let stored_oracle = client.oracle();
        client.update_price(&actor, &stored_oracle, &1_000_i128);
        assert_eq!(client.get_price(), 1_000);
    }

    /// ✅ Secure path rejects a price update from an unwhitelisted address.
    #[test]
    #[should_panic(expected = "oracle not whitelisted")]
    fn test_secure_fake_oracle_rejected() {
        let (env, _admin, actor, client) = setup_secure();
        let fake_oracle_id = env.register_contract(None, FakeOracle);
        let fake_oracle = Address::from_contract_id(&fake_oracle_id);
        // ✅ SECURE: fake oracle is rejected before price is stored
        client.update_price(&actor, &fake_oracle, &i128::MAX);
    }

    /// Boundary: even a random wallet address is rejected by the secure path.
    #[test]
    #[should_panic(expected = "oracle not whitelisted")]
    fn test_secure_random_address_rejected() {
        let (env, _admin, actor, client) = setup_secure();
        let random = Address::generate(&env);
        client.update_price(&actor, &random, &999_999_999_i128);
    }
}
