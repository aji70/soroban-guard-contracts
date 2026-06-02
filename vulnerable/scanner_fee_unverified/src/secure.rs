//! SECURE: Scanner Registry with Balance-Delta Fee Verification
//!
//! FIXES APPLIED:
//! 1. `register_scanner` snapshots the contract's token balance before and
//!    after the transfer call.
//! 2. Registration is only completed if the delta equals or exceeds
//!    `REGISTRATION_FEE`, rejecting fee-on-transfer under-payment.

use super::{token, DataKey, REGISTRATION_FEE};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureRegistry;

#[contractimpl]
impl SecureRegistry {
    pub fn initialize(env: Env, token: Address) {
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// SECURE: verifies the balance delta equals REGISTRATION_FEE before
    /// completing registration.
    ///
    /// # Panics
    /// - If the received amount (post - pre balance) is less than `REGISTRATION_FEE`.
    pub fn register_scanner(env: Env, scanner: Address) {
        scanner.require_auth();
        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);
        let contract_addr = env.current_contract_address();

        // ✅ FIX: snapshot balance before transfer.
        let pre: i128 = token_client.balance(&contract_addr);

        token_client.transfer(&scanner, &contract_addr, &REGISTRATION_FEE);

        // ✅ FIX: snapshot balance after transfer and assert full fee received.
        let post: i128 = token_client.balance(&contract_addr);
        let received = post - pre;
        assert!(
            received >= REGISTRATION_FEE,
            "insufficient fee received after transfer"
        );

        env.storage()
            .persistent()
            .set(&DataKey::Registered(scanner), &true);
    }

    /// Returns whether `scanner` is registered.
    pub fn is_registered(env: Env, scanner: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Registered(scanner))
            .unwrap_or(false)
    }
}
