//! SECURE: Airdrop with Expiry Enforcement and Admin Reclaim
//!
//! The claim function checks env.ledger().sequence() <= expiry_ledger and rejects
//! claims after expiry. Admin has a reclaim_expired_funds() function to recover
//! remaining balance after the campaign expires.

use super::{hash_pair, DataKey};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Vec,
};

pub fn leaf_hash(env: &Env, claimant: &Address, amount: i128) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    env.crypto().sha256(&data).into()
}

pub fn build_tree(
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

fn verify_merkle_proof_secure(
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
pub struct SecureAirdrop;

#[contractimpl]
impl SecureAirdrop {
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

    /// ✅ SECURE: Claim with expiry check.
    /// Rejects any claim after env.ledger().sequence() > expiry_ledger.
    pub fn claim(
        env: Env,
        claimant: Address,
        amount: i128,
        proof: Vec<BytesN<32>>,
    ) {
        claimant.require_auth();

        // ✅ SECURE: Check expiry before accepting claim.
        let expiry_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ExpiryLedger)
            .expect("expiry not set");

        let current_ledger = env.ledger().sequence();
        assert!(
            current_ledger <= expiry_ledger,
            "campaign has expired"
        );

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
        verify_merkle_proof_secure(&env, &claimant, amount, &proof, &root);

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

    /// ✅ SECURE: Admin function to reclaim remaining balance after expiry.
    pub fn reclaim_expired_funds(env: Env, admin: Address) {
        admin.require_auth();

        let expiry_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ExpiryLedger)
            .expect("expiry not set");

        let current_ledger = env.ledger().sequence();
        assert!(
            current_ledger > expiry_ledger,
            "campaign not yet expired"
        );

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);

        // Set balance to zero (amount reclaimed).
        env.storage().persistent().set(&DataKey::Balance, &0);

        env.events()
            .publish((symbol_short!("reclaim"),), (admin, balance));
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
