//! VULNERABLE: Escrow Release Sends to Hardcoded Address
//!
//! An escrow contract where `release` transfers funds to a compile-time
//! constant address instead of reading the beneficiary from storage. Every
//! escrow — regardless of which beneficiary was recorded at creation — will
//! have its funds sent to the same hardcoded address.
//!
//! VULNERABILITY: `release` ignores the stored beneficiary and uses a
//! hardcoded `Address` constant, causing critical fund loss for all escrows
//! whose beneficiary differs from that constant.
//! Severity: Critical
//!
//! Fix: read the beneficiary from persistent storage keyed by `escrow_id`,
//! set it immutably during `create_escrow`, and require admin auth to release.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Beneficiary(u64), // escrow_id → intended beneficiary
    Balance(u64),     // escrow_id → locked amount
    // Internal ledger used instead of a real token client so tests are
    // self-contained (no deployed token contract required).
    Wallet(Address),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn wallet_balance(env: &Env, addr: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Wallet(addr.clone()))
        .unwrap_or(0)
}

fn credit(env: &Env, addr: &Address, amount: i128) {
    let bal = wallet_balance(env, addr);
    env.storage()
        .persistent()
        .set(&DataKey::Wallet(addr.clone()), &(bal + amount));
}

fn debit(env: &Env, addr: &Address, amount: i128) {
    let bal = wallet_balance(env, addr);
    assert!(bal >= amount, "insufficient funds");
    env.storage()
        .persistent()
        .set(&DataKey::Wallet(addr.clone()), &(bal - amount));
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableEscrow;

#[contractimpl]
impl VulnerableEscrow {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Fund the contract's internal wallet (simulates token deposit).
    pub fn fund(env: Env, sender: Address, amount: i128) {
        sender.require_auth();
        credit(&env, &sender, amount);
    }

    /// Create an escrow locking `amount` for `beneficiary`.
    /// The beneficiary is stored in persistent storage keyed by `escrow_id`.
    pub fn create_escrow(env: Env, escrow_id: u64, depositor: Address, beneficiary: Address, amount: i128) {
        depositor.require_auth();
        debit(&env, &depositor, amount);
        env.storage()
            .persistent()
            .set(&DataKey::Beneficiary(escrow_id), &beneficiary);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(escrow_id), &amount);
    }

    /// VULNERABLE: ignores the stored beneficiary — always sends to the
    /// hardcoded address baked in at the call site.
    ///
    /// In a real deployment this would be a compile-time constant address
    /// string. Here we accept it as a parameter named `hardcoded` to make
    /// the bug observable in tests without needing a real Stellar address.
    pub fn release_vulnerable(env: Env, escrow_id: u64, hardcoded: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(escrow_id))
            .expect("escrow not found");

        // ❌ Ignores stored beneficiary — sends to hardcoded address instead
        credit(&env, &hardcoded, amount);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(escrow_id), &0_i128);
    }

    /// SECURE: reads the beneficiary from storage — funds go to the right address.
    pub fn release_secure(env: Env, escrow_id: u64) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let beneficiary: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Beneficiary(escrow_id))
            .expect("beneficiary not set");

        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(escrow_id))
            .expect("escrow not found");

        // ✅ Reads from storage — correct beneficiary receives funds
        credit(&env, &beneficiary, amount);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(escrow_id), &0_i128);
    }

    pub fn wallet_balance(env: Env, addr: Address) -> i128 {
        wallet_balance(&env, &addr)
    }

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

    fn setup() -> (Env, VulnerableEscrowClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableEscrow);
        let client = VulnerableEscrowClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, client, admin)
    }

    /// DEMONSTRATES VULNERABILITY: escrow created for beneficiary_a is
    /// released to the hardcoded address, not beneficiary_a.
    #[test]
    fn test_release_sends_to_hardcoded_not_stored_beneficiary() {
        let (env, client, _admin) = setup();

        let depositor = Address::generate(&env);
        let beneficiary_a = Address::generate(&env);
        let hardcoded = Address::generate(&env); // simulates compile-time constant

        client.fund(&depositor, &1000);
        client.create_escrow(&1, &depositor, &beneficiary_a, &500);

        // ❌ Vulnerable release — funds go to hardcoded, not beneficiary_a
        client.release_vulnerable(&1, &hardcoded);

        assert_eq!(
            client.wallet_balance(&hardcoded),
            500,
            "hardcoded address received funds (bug)"
        );
        assert_eq!(
            client.wallet_balance(&beneficiary_a),
            0,
            "intended beneficiary received nothing (bug)"
        );
    }

    /// After the fix, funds are sent to the stored beneficiary.
    #[test]
    fn test_secure_release_sends_to_stored_beneficiary() {
        let (env, client, _admin) = setup();

        let depositor = Address::generate(&env);
        let beneficiary = Address::generate(&env);

        client.fund(&depositor, &1000);
        client.create_escrow(&2, &depositor, &beneficiary, &750);

        // ✅ Secure release — reads beneficiary from storage
        client.release_secure(&2);

        assert_eq!(
            client.wallet_balance(&beneficiary),
            750,
            "stored beneficiary received correct funds"
        );
        assert_eq!(client.escrow_balance(&2), 0);
    }

    /// Two escrows with different beneficiaries each release to their own
    /// correct address when using the secure path.
    #[test]
    fn test_two_escrows_release_to_respective_beneficiaries() {
        let (env, client, _admin) = setup();

        let depositor = Address::generate(&env);
        let beneficiary_x = Address::generate(&env);
        let beneficiary_y = Address::generate(&env);

        client.fund(&depositor, &2000);
        client.create_escrow(&10, &depositor, &beneficiary_x, &600);
        client.create_escrow(&11, &depositor, &beneficiary_y, &400);

        client.release_secure(&10);
        client.release_secure(&11);

        assert_eq!(client.wallet_balance(&beneficiary_x), 600);
        assert_eq!(client.wallet_balance(&beneficiary_y), 400);
        assert_eq!(client.escrow_balance(&10), 0);
        assert_eq!(client.escrow_balance(&11), 0);
    }
}
