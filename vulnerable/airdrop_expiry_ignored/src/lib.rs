//! VULNERABLE: Expired Airdrop Claims Remain Valid Forever
//!
//! A campaign airdrop that stores an expiry_ledger at initialization but the
//! claim function never reads or checks it. Old proofs remain valid indefinitely
//! and can drain leftover funds long after the campaign should be closed.
//!
//! VULNERABILITY: The claim function never checks env.ledger().sequence() <= expiry_ledger.
//!
//! SECURE MIRROR: `secure::SecureAirdrop` checks expiry in claim() and provides
//! reclaim_expired_funds() for admin to recover remaining balance after expiry.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Vec,
};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    ExpiryLedger,
    Balance,
    Claimed(Address),
    MerkleRoot,
}

pub fn leaf_hash(env: &Env, claimant: &Address, amount: i128) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    env.crypto().sha256(&data).into()
}

pub fn hash_pair(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
    let mut data = Bytes::new(env);
    if a <= b {
        data.append(&Bytes::from(a.clone()));
        data.append(&Bytes::from(b.clone()));
    } else {
        data.append(&Bytes::from(b.clone()));
        data.append(&Bytes::from(a.clone()));
    }
    env.crypto().sha256(&data).into()
}

pub fn verify_merkle_proof(
    env: &Env,
    claimant: &Address,
    amount: i128,
    proof: &Vec<BytesN<32>>,
    root: &BytesN<32>,
) {
    let mut node = leaf_hash(env, claimant, amount);
    for sibling in proof.iter() {
        node = hash_pair(env, &node, &sibling);
    }
    assert!(node == *root, "invalid merkle proof");
}

#[contract]
pub struct VulnerableAirdrop;

#[contractimpl]
impl VulnerableAirdrop {
    /// Initialize the campaign with admin, expiry ledger, and initial balance.
    pub fn initialize(env: Env, admin: Address, expiry_ledger: u32, initial_balance: i128) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::ExpiryLedger, &expiry_ledger);
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &initial_balance);
        env.events().publish(
            (symbol_short!("init"),),
            (admin, expiry_ledger, initial_balance),
        );
    }

    /// Set the merkle root for proofs.
    pub fn set_merkle_root(env: Env, root: BytesN<32>) {
        Self::require_admin_auth(&env);
        env.storage().persistent().set(&DataKey::MerkleRoot, &root);
    }

    /// Get current balance.
    pub fn get_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0)
    }

    /// Get expiry ledger.
    pub fn get_expiry_ledger(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::ExpiryLedger)
            .unwrap_or(0)
    }

    /// ❌ VULNERABLE: Claim without checking expiry.
    /// The function never reads env.ledger().sequence() or checks expiry_ledger.
    pub fn claim(
        env: Env,
        claimant: Address,
        amount: i128,
        proof: Vec<BytesN<32>>,
    ) {
        claimant.require_auth();

        // Check if already claimed.
        assert!(
            !env.storage()
                .persistent()
                .get(&DataKey::Claimed(claimant.clone()))
                .unwrap_or(false),
            "already claimed"
        );

        // Get merkle root.
        let root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::MerkleRoot)
            .expect("merkle root not set");

        // Verify proof.
        verify_merkle_proof(&env, &claimant, amount, &proof, &root);

        // ❌ VULNERABLE: No expiry check! Old proofs work forever.
        // Missing: assert!(env.ledger().sequence() <= expiry_ledger);

        // Mark as claimed.
        env.storage()
            .persistent()
            .set(&DataKey::Claimed(claimant.clone()), &true);

        // Transfer (or record) the amount.
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        let new_balance = balance - amount;
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &new_balance);

        env.events()
            .publish((symbol_short!("claim"),), (claimant, amount));
    }

    /// Check if address has claimed.
    pub fn is_claimed(env: Env, claimant: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Claimed(claimant))
            .unwrap_or(false)
    }

    fn require_admin_auth(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("contract not initialized");
        admin.require_auth();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Env};

    fn build_tree(
        env: &Env,
        claimant: &Address,
        amount: i128,
        other: &Address,
    ) -> (BytesN<32>, Vec<BytesN<32>>) {
        let leaf0 = leaf_hash(env, claimant, amount);
        let leaf1 = leaf_hash(env, other, 0i128);
        let root = hash_pair(env, &leaf0, &leaf1);
        let mut proof = Vec::new(env);
        proof.push_back(leaf1);
        (root, proof)
    }

    #[test]
    fn test_claim_after_expiry_still_works() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        // Initialize with expiry at ledger 100.
        client.initialize(&admin, &100, &1000);

        // Set merkle root.
        let (root, proof) = build_tree(&env, &claimant, 500, &other);
        client.set_merkle_root(&root);

        // Advance ledger past expiry (to 150).
        env.ledger().set_sequence_number(150);

        // ❌ VULNERABLE: Claim after expiry still succeeds!
        client.claim(&claimant, &500, &proof);
        assert!(client.is_claimed(&claimant));
        assert_eq!(client.get_balance(), 500i128);
    }

    #[test]
    fn test_boundary_claim_at_exactly_expiry_plus_one() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        // Initialize with expiry at ledger 100.
        client.initialize(&admin, &100, &1000);

        let (root, proof) = build_tree(&env, &claimant, 500, &other);
        client.set_merkle_root(&root);

        // Advance to expiry + 1 (ledger 101).
        env.ledger().set_sequence_number(101);

        // ❌ VULNERABLE: Claim at exactly expiry + 1 still works!
        client.claim(&claimant, &500, &proof);
        assert!(client.is_claimed(&claimant));
    }

    #[test]
    fn test_secure_rejects_expired_claim() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureAirdrop);
        let client = secure::SecureAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        // Initialize with expiry at ledger 100.
        client.initialize(&admin, &100, &1000);

        let (root, proof) = secure::build_tree(&env, &claimant, 500, &other);
        client.set_merkle_root(&root);

        // Advance past expiry to ledger 150.
        env.ledger().set_sequence_number(150);

        // ✅ Secure path: Claim is rejected after expiry.
        let result = client.try_claim(&claimant, &500, &proof);
        assert!(result.is_err(), "secure path rejects expired claim");
    }

    #[test]
    fn test_secure_reclaim_after_expiry() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureAirdrop);
        let client = secure::SecureAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        // Initialize with expiry at ledger 50, balance 1000.
        client.initialize(&admin, &50, &1000);

        let (root, proof) = secure::build_tree(&env, &claimant, 500, &other);
        client.set_merkle_root(&root);

        // Claim before expiry (at ledger 40).
        env.ledger().set_sequence_number(40);
        client.claim(&claimant, &500, &proof);
        assert_eq!(client.get_balance(), 500i128);

        // Advance past expiry (to ledger 60).
        env.ledger().set_sequence_number(60);

        // ✅ Admin can reclaim the remaining balance.
        client.reclaim_expired_funds(&admin);
        // After reclaim, balance should be empty or transferred.
        // (The secure implementation determines final state.)
    }
}
