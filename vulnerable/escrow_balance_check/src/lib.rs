//! VULNERABLE: Missing Escrow Balance Check Before Release
//!
//! An escrow contract where the `release` function transfers funds to the
//! beneficiary without first verifying that the escrow's recorded balance is
//! sufficient to cover the release amount.
//!
//! VULNERABILITY: `release()` reads the stored escrow balance but never
//! asserts it is >= `amount` before transferring. If the stored balance is
//! stale or has been manipulated, the contract will subtract more than it
//! holds, causing an arithmetic underflow in the internal ledger and leaving
//! state permanently inconsistent.
//!
//! SECURE MIRROR: `secure::SecureEscrow` adds an explicit
//! `if escrow_balance < amount { panic!("insufficient escrow balance") }`
//! guard before the transfer and zeroes the entry on a full release.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(u64),      // escrow_id -> locked amount
    Beneficiary(u64),  // escrow_id -> beneficiary address
}

// ── Vulnerable contract ───────────────────────────────────────────────────────

#[contract]
pub struct VulnerableEscrow;

#[contractimpl]
impl VulnerableEscrow {
    /// Initialise with an admin. Guards against re-initialisation.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Deposit `amount` into escrow slot `escrow_id` for `beneficiary`.
    /// Requires admin auth (admin controls escrow creation).
    pub fn deposit(env: Env, escrow_id: u64, beneficiary: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(escrow_id))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(escrow_id), &(current + amount));
        env.storage()
            .persistent()
            .set(&DataKey::Beneficiary(escrow_id), &beneficiary);
    }

    /// VULNERABLE: transfers `amount` to the beneficiary without checking
    /// that the stored escrow balance is >= `amount`.
    ///
    /// # Vulnerability
    /// Missing balance guard. Impact: the internal balance can underflow,
    /// leaving the ledger in an inconsistent state.
    pub fn release(env: Env, escrow_id: u64, amount: i128) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let beneficiary: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Beneficiary(escrow_id))
            .expect("escrow not found");

        let escrow_balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(escrow_id))
            .unwrap_or(0);

        // ❌ Missing: if escrow_balance < amount { panic!("insufficient escrow balance") }

        // Simulate the token transfer by adjusting the internal balance.
        // In a real contract this would call token_client.transfer(...).
        let new_balance = escrow_balance - amount; // underflows when amount > balance
        env.storage()
            .persistent()
            .set(&DataKey::Balance(escrow_id), &new_balance);

        // Record the release destination (mirrors what a token transfer would do).
        env.storage()
            .persistent()
            .set(&DataKey::Beneficiary(escrow_id), &beneficiary);
    }

    /// Returns the recorded balance for `escrow_id`.
    pub fn escrow_balance(env: Env, escrow_id: u64) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(escrow_id))
            .unwrap_or(0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableEscrowClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableEscrow);
        let client = VulnerableEscrowClient::new(&env, &id);
        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin, beneficiary)
    }

    /// Demonstrates the bug: releasing more than the deposited balance does
    /// NOT panic — the internal balance silently underflows to a negative value.
    #[test]
    fn test_release_exceeding_balance_does_not_revert() {
        let (_env, client, _admin, beneficiary) = setup();
        client.deposit(&1, &beneficiary, &500);

        // Release 1000 when only 500 is held — should panic in a correct
        // implementation, but the vulnerable contract allows it.
        client.release(&1, &1000);

        // Balance has underflowed to -500, demonstrating the bug.
        assert_eq!(client.escrow_balance(&1), -500);
    }

    /// A valid release of the exact balance succeeds and zeroes the entry.
    #[test]
    fn test_valid_release_exact_balance_succeeds() {
        let (_env, client, _admin, beneficiary) = setup();
        client.deposit(&2, &beneficiary, &1000);
        client.release(&2, &1000);
        assert_eq!(client.escrow_balance(&2), 0);
    }
}
