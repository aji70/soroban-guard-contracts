//! VULNERABLE: Cross-Contract Error Converted to Success Status
//!
//! A lending contract calls an external token transfer to move funds, then
//! updates its internal accounting. When the token transfer fails, the
//! contract catches the error, treats it as a no-op, and still updates the
//! internal balance — crediting the user without any real transfer occurring.
//!
//! VULNERABILITY: the `Result` from the cross-contract call is unwrapped with
//! a fallback default instead of being propagated. State is written regardless
//! of whether the external call succeeded.
//!
//! SECURE MIRROR: `secure::SecureLending` propagates the error and only
//! updates state after a confirmed successful transfer.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    /// Internal credited balance for a user.
    CreditBalance(Address),
    /// Simulated flag: when true the mock token transfer will fail.
    TransferFails,
}

#[contract]
pub struct VulnerableLending;

#[contractimpl]
impl VulnerableLending {
    pub fn initialize(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::TransferFails, &false);
    }

    /// Toggle the simulated token-transfer failure flag.
    pub fn set_transfer_fails(env: Env, fails: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::TransferFails, &fails);
    }

    /// Simulated cross-contract token transfer.
    /// Returns `Ok(())` normally, `Err(())` when the failure flag is set.
    fn do_token_transfer(env: &Env) -> Result<(), ()> {
        let fails: bool = env
            .storage()
            .persistent()
            .get(&DataKey::TransferFails)
            .unwrap_or(false);
        if fails {
            Err(())
        } else {
            Ok(())
        }
    }

    /// VULNERABLE: swallows the transfer error and credits the user anyway.
    ///
    /// # Vulnerability
    /// `do_token_transfer` failure is caught and ignored via `.unwrap_or(())`.
    /// The internal balance is updated even when no real transfer occurred.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();

        // ❌ Error is swallowed — transfer failure is treated as success.
        let _ = Self::do_token_transfer(&env).unwrap_or(());

        let key = DataKey::CreditBalance(user.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    pub fn credit_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CreditBalance(user))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableLendingClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableLending);
        let client = VulnerableLendingClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();
        (env, client)
    }

    /// Vulnerable path: transfer fails but internal balance is still credited.
    #[test]
    fn test_vulnerable_balance_credited_despite_transfer_failure() {
        let (env, client) = setup();
        let user = Address::generate(&env);

        client.set_transfer_fails(&true);
        client.deposit(&user, &1000);

        // Transfer failed, but the vulnerable contract credited the balance anyway.
        assert_eq!(
            client.credit_balance(&user),
            1000,
            "vulnerable: balance credited despite failed transfer"
        );
    }

    /// Boundary: when transfer succeeds, balance should be credited in both versions.
    #[test]
    fn test_successful_transfer_credits_balance() {
        let (env, client) = setup();
        let user = Address::generate(&env);

        client.set_transfer_fails(&false);
        client.deposit(&user, &500);
        assert_eq!(client.credit_balance(&user), 500);
    }

    /// Secure path: failed transfer must leave state unchanged.
    #[test]
    fn test_secure_state_unchanged_on_transfer_failure() {
        use crate::secure::SecureLendingClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();

        let user = Address::generate(&env);
        client.set_transfer_fails(&true);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.deposit(&user, &1000);
        }));
        assert!(result.is_err(), "secure deposit must panic on transfer failure");
        assert_eq!(
            client.credit_balance(&user),
            0,
            "secure: state must remain unchanged"
        );
    }

    /// Secure path: successful transfer credits balance correctly.
    #[test]
    fn test_secure_credits_balance_on_success() {
        use crate::secure::SecureLendingClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureLending);
        let client = SecureLendingClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();

        let user = Address::generate(&env);
        client.set_transfer_fails(&false);
        client.deposit(&user, &750);
        assert_eq!(client.credit_balance(&user), 750);
    }
}
