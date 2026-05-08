//! VULNERABLE: Unprotected Fee Withdrawal
//!
//! A DEX-style contract that accumulates fees from swaps and exposes an
//! unguarded `withdraw_fees()` function. Any account can drain the contract's
//! accumulated fee balance to an arbitrary address.
//!
//! VULNERABILITY: `withdraw_fees()` mutates storage and transfers funds without
//! calling `admin.require_auth()`, allowing anyone to steal accumulated fees.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Fees,
}

#[contract]
pub struct UnprotectedFeeWithdraw;

#[contractimpl]
impl UnprotectedFeeWithdraw {
    /// Initialise the contract with an admin and zero fee balance. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
    }

    /// Simulate a swap that accumulates a fee proportional to `fee_rate` basis points.
    pub fn swap(env: Env, amount_in: i128, fee_rate: i128) {
        // In a real DEX, this would validate the swap and transfer tokens.
        // For this example, we just accumulate fees.
        let fee = (amount_in * fee_rate) / 10000;
        let current_fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        let new_fees = current_fees + fee;
        env.storage().persistent().set(&DataKey::Fees, &new_fees);

        env.events()
            .publish((symbol_short!("swap"),), (amount_in, fee_rate, fee));
    }

    /// VULNERABLE: Withdraws accumulated fees to an arbitrary recipient without
    /// verifying that the caller is the admin. Any account can call this and
    /// drain the contract's fee balance.
    pub fn withdraw_fees(env: Env, recipient: Address) {
        // ❌ Missing: let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        //             admin.require_auth();

        let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Fees, &0i128);

        // In a real contract, this would transfer tokens to the recipient.
        // For this example, we just emit an event to demonstrate the vulnerability.
        env.events()
            .publish((symbol_short!("wdraw_fee"),), (recipient.clone(), fees));
    }

    /// Returns the accumulated fee balance, defaulting to 0.
    pub fn get_fees(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Fees).unwrap_or(0)
    }

    /// Returns the stored admin address. Panics if not initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, UnprotectedFeeWithdrawClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, UnprotectedFeeWithdraw);
        let client = UnprotectedFeeWithdrawClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, admin, client)
    }

    #[test]
    fn test_admin_withdraws_fees_normally() {
        let (env, admin, client) = setup();
        client.swap(&1000, &25);
        client.swap(&2000, &25);
        assert_eq!(client.get_fees(), 7);
        client.withdraw_fees(&admin);
        assert_eq!(client.get_fees(), 0);
    }

    #[test]
    fn test_attacker_withdraws_fees_without_auth() {
        let (_env, _admin, client) = setup();
        let env = Env::default();
        let attacker = Address::generate(&env);
        client.swap(&1000, &25);
        client.swap(&2000, &25);
        assert_eq!(client.get_fees(), 7);
        // ❌ VULNERABILITY: No auth check — attacker drains fees freely.
        client.withdraw_fees(&attacker);
        assert_eq!(client.get_fees(), 0);
    }

    #[test]
    fn test_fee_balance_zeroed_after_withdrawal() {
        let (env, admin, client) = setup();
        client.swap(&5000, &50);
        assert_eq!(client.get_fees(), 25);
        client.withdraw_fees(&admin);
        assert_eq!(client.get_fees(), 0);
    }
}
