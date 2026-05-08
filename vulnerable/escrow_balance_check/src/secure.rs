//! SECURE: Escrow Release With Balance Check
//!
//! Identical API to VulnerableEscrow but `release` guards against releasing
//! more than the recorded escrow balance before adjusting state.

use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureEscrow;

#[contractimpl]
impl SecureEscrow {
    /// Initialise with an admin. Guards against re-initialisation.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Deposit `amount` into escrow slot `escrow_id` for `beneficiary`.
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

    /// ✅ SECURE: checks that the escrow holds at least `amount` before
    /// releasing. Uses `checked_sub` to prevent any arithmetic underflow.
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

        // ✅ FIX: explicit balance guard before any state mutation.
        if escrow_balance < amount {
            panic!("insufficient escrow balance");
        }

        // ✅ FIX: use checked_sub as a second line of defence against underflow.
        let new_balance = escrow_balance
            .checked_sub(amount)
            .expect("insufficient escrow balance");

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

    fn setup() -> (Env, SecureEscrowClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureEscrow);
        let client = SecureEscrowClient::new(&env, &id);
        let admin = Address::generate(&env);
        let beneficiary = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin, beneficiary)
    }

    /// After the fix, releasing more than the balance panics.
    #[test]
    #[should_panic(expected = "insufficient escrow balance")]
    fn test_release_exceeding_balance_panics() {
        let (_env, client, _admin, beneficiary) = setup();
        client.deposit(&1, &beneficiary, &500);
        // 1000 > 500 — must panic.
        client.release(&1, &1000);
    }

    /// A valid release of the exact balance succeeds and zeroes the entry.
    #[test]
    fn test_valid_release_exact_balance_succeeds() {
        let (_env, client, _admin, beneficiary) = setup();
        client.deposit(&2, &beneficiary, &1000);
        client.release(&2, &1000);
        assert_eq!(client.escrow_balance(&2), 0);
    }

    /// A partial release reduces the balance correctly.
    #[test]
    fn test_partial_release_reduces_balance() {
        let (_env, client, _admin, beneficiary) = setup();
        client.deposit(&3, &beneficiary, &1000);
        client.release(&3, &400);
        assert_eq!(client.escrow_balance(&3), 600);
    }
}
