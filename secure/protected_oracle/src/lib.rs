//! SECURE: Protected Oracle — Minimum-Ledger-Delay Price Consumption
//!
//! Fixes the instant-oracle vulnerability by requiring that at least
//! `MIN_DELAY` ledgers have elapsed between a price update and any
//! consumption of that price. This makes same-ledger (flash-loan-style)
//! price manipulation impossible.
//!
//! SECURITY: ✅ `get_price` panics if the stored price was updated fewer
//! than `MIN_DELAY` ledgers ago, ensuring no atomic set-then-read exploit.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

/// Minimum number of ledgers that must pass after `set_price` before
/// `get_price` will return the new value.
const MIN_DELAY: u32 = 5;

#[contracttype]
pub enum DataKey {
    Price,
    UpdatedAt,
    Admin,
}

#[contract]
pub struct ProtectedOracle;

#[contractimpl]
impl ProtectedOracle {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Update the price. The new value is not consumable until
    /// `MIN_DELAY` ledgers have passed.
    pub fn set_price(env: Env, caller: Address, price: i128) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }
        env.storage().instance().set(&DataKey::Price, &price);
        env.storage()
            .instance()
            .set(&DataKey::UpdatedAt, &env.ledger().sequence());
    }

    /// Return the current price only if it is at least `MIN_DELAY` ledgers old.
    /// ✅ SECURE: Prevents same-ledger price manipulation.
    pub fn get_price(env: Env) -> i128 {
        let updated_at: u32 = env
            .storage()
            .instance()
            .get(&DataKey::UpdatedAt)
            .unwrap_or(0);
        let current = env.ledger().sequence();
        if current < updated_at + MIN_DELAY {
            panic!("price not yet available: delay not elapsed");
        }
        env.storage().instance().get(&DataKey::Price).unwrap_or(0)
    }

    pub fn updated_at(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::UpdatedAt)
            .unwrap_or(0)
    }

    pub fn min_delay(_env: Env) -> u32 {
        MIN_DELAY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, Env};

    fn setup() -> (Env, Address, ProtectedOracleClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, ProtectedOracle);
        let client = ProtectedOracleClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    /// Price is not readable in the same ledger it was set.
    #[test]
    #[should_panic(expected = "price not yet available: delay not elapsed")]
    fn test_get_price_same_ledger_panics() {
        let (env, admin, client) = setup();

        env.ledger().set_sequence_number(100);
        client.set_price(&admin, &500);

        // ✅ SECURE: same-ledger read is rejected
        client.get_price();
    }

    /// Price is not readable before MIN_DELAY ledgers have passed.
    #[test]
    #[should_panic(expected = "price not yet available: delay not elapsed")]
    fn test_get_price_before_delay_panics() {
        let (env, admin, client) = setup();

        env.ledger().set_sequence_number(100);
        client.set_price(&admin, &500);

        // Only 4 ledgers later — still within delay window
        env.ledger().set_sequence_number(104);
        client.get_price();
    }

    /// Price is readable after MIN_DELAY ledgers have passed.
    #[test]
    fn test_get_price_after_delay_succeeds() {
        let (env, admin, client) = setup();

        env.ledger().set_sequence_number(100);
        client.set_price(&admin, &500);

        // Exactly MIN_DELAY ledgers later
        env.ledger().set_sequence_number(105);
        assert_eq!(client.get_price(), 500);
    }

    /// Secure version blocks the flash-loan-style manipulation attack.
    #[test]
    #[should_panic(expected = "price not yet available: delay not elapsed")]
    fn test_flash_loan_attack_blocked() {
        let (env, admin, client) = setup();

        env.ledger().set_sequence_number(50);

        // Attacker sets an inflated price
        client.set_price(&admin, &1000);

        // ✅ SECURE: immediate read is blocked — attack cannot proceed
        client.get_price();
    }
}
