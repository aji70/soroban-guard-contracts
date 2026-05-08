//! VULNERABLE: Instant Oracle — Flash-Loan Price Manipulation
//!
//! An oracle that allows `set_price` and `get_price` to be called in the same
//! ledger enforces no delay between a price update and its consumption.
//! An attacker can borrow funds, call `set_price` to an arbitrary value,
//! exploit any contract that reads the oracle in the same transaction, then
//! repay — a classic flash-loan price manipulation.
//!
//! VULNERABILITY: No minimum ledger delay between price write and price read.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Price,
    UpdatedAt,
}

pub(crate) fn get_admin(env: &Env) -> Address {
    env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized")
}

#[contract]
pub struct InstantOracle;

#[contractimpl]
impl InstantOracle {
    /// Initialise the oracle with an admin. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: price is immediately readable in the same ledger.
    pub fn set_price(env: Env, price: i128) {
        let admin = get_admin(&env);
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Price, &price);
        let seq = env.ledger().sequence();
        env.storage().persistent().set(&DataKey::UpdatedAt, &seq);
    }

    /// ❌ No delay check — returns whatever was just written.
    pub fn get_price(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Price).unwrap_or(0)
    }

    /// Returns the ledger sequence at which the price was last updated.
    pub fn updated_at(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::UpdatedAt)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Ledger as _},
        Address, Env,
    };

    fn setup(env: &Env) -> (InstantOracleClient, Address) {
        let id = env.register_contract(None, InstantOracle);
        let client = InstantOracleClient::new(env, &id);
        let admin = Address::generate(env);
        env.mock_all_auths();
        client.initialize(&admin);
        (client, admin)
    }

    /// Demonstrates the vulnerability: price set and read in the same ledger.
    #[test]
    fn test_price_set_and_read_same_ledger() {
        let env = Env::default();
        let (client, _) = setup(&env);

        env.mock_all_auths();
        client.set_price(&1_000_000);

        // Same ledger — no delay enforced, price is immediately available.
        let price = client.get_price();
        assert_eq!(price, 1_000_000);
        assert_eq!(client.updated_at(), env.ledger().sequence());
    }

    /// Demonstrates a dependent contract reading a manipulated price in the
    /// same ledger the attacker set it — flash-loan style.
    #[test]
    fn test_dependent_contract_uses_manipulated_price() {
        let env = Env::default();
        let (oracle, _) = setup(&env);

        env.mock_all_auths();

        // Attacker pumps price to an extreme value.
        oracle.set_price(&999_999_999);

        // A dependent contract (simulated inline) reads the oracle immediately.
        let manipulated = oracle.get_price();

        // Collateral calculation based on manipulated price — wildly inflated.
        let collateral_value = manipulated * 10; // e.g. 10 units at oracle price
        assert_eq!(collateral_value, 9_999_999_990);

        // ❌ Attacker exploits the inflated collateral value in the same ledger.
        assert_eq!(oracle.updated_at(), env.ledger().sequence());
    }

    // ---- secure mirror tests -----------------------------------------------

    #[test]
    fn test_secure_price_readable_after_delay() {
        use crate::secure::SecureOracleClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureOracle);
        let client = SecureOracleClient::new(&env, &id);
        let admin = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin, &5); // 5-ledger delay

        client.set_price(&500);

        // Advance past the delay window.
        env.ledger()
            .set_sequence_number(env.ledger().sequence() + 6);

        assert_eq!(client.get_price(), 500);
    }

    #[test]
    #[should_panic(expected = "price not yet valid")]
    fn test_secure_price_not_readable_before_delay() {
        use crate::secure::SecureOracleClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureOracle);
        let client = SecureOracleClient::new(&env, &id);
        let admin = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin, &5);

        client.set_price(&500);

        // Still within the delay window — must panic.
        client.get_price();
    }
}
