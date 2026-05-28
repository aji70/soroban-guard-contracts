//! VULNERABLE: Merkle Leaf Omits Token Amount
//!
//! The contract constructs Merkle leaves using only the claimant address,
//! omitting the claimed amount. This allows an attacker to claim any amount
//! as long as their address is in the tree, since the proof verification
//! does not bind the amount to the leaf.
//!
//! VULNERABILITY: `leaf_hash()` includes only address, not amount. Any amount
//! passed to `claim()` is accepted if the address is in the tree.
//!
//! SECURE MIRROR: `secure::SecureAirdrop` includes amount, campaign_id, and
//! domain in the leaf hash, binding the claimed amount to the proof.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Bytes, BytesN, Env, Vec,
    xdr::ToXdr,
};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    MerkleRoot,
    Token,
    CampaignId,
    Domain,
    Claimed(Address),
}

#[contract]
pub struct VulnerableAirdrop;

// ❌ VULNERABLE: leaf hash includes only address, missing amount
fn leaf_hash(env: &Env, claimant: &Address) -> BytesN<32> {
    env.crypto().sha256(&claimant.to_xdr(env)).into()
}

/// Hash two 32-byte nodes together, smaller first (canonical ordering).
fn hash_pair(env: &Env, a: &BytesN<32>, b: &BytesN<32>) -> BytesN<32> {
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

// ❌ VULNERABLE: amount is not included in verification
fn verify_merkle_proof(env: &Env, claimant: &Address, proof: &Vec<BytesN<32>>) {
    let root: BytesN<32> = env
        .storage()
        .persistent()
        .get(&DataKey::MerkleRoot)
        .expect("not initialized");

    let mut node = leaf_hash(env, claimant);
    for sibling in proof.iter() {
        node = hash_pair(env, &node, &sibling);
    }
    assert!(node == root, "invalid merkle proof");
}

fn is_claimed(env: &Env, claimant: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Claimed(claimant.clone()))
        .unwrap_or(false)
}

fn mark_claimed(env: &Env, claimant: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::Claimed(claimant.clone()), &true);
}

#[contractimpl]
impl VulnerableAirdrop {
    pub fn initialize(
        env: Env,
        admin: Address,
        merkle_root: BytesN<32>,
        token: Address,
        campaign_id: u32,
    ) {
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &merkle_root);
        env.storage().persistent().set(&DataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&DataKey::CampaignId, &campaign_id);
        env.storage()
            .persistent()
            .set(&DataKey::Domain, &env.current_contract_address());
    }

    /// Admin deposits tokens into the airdrop pool.
    pub fn fund(env: Env, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(&admin, &env.current_contract_address(), &amount);

        env.events()
            .publish((symbol_short!("fund"),), (admin, amount));
    }

    /// VULNERABLE: claim verification does not include amount in the proof.
    /// An attacker can claim any amount as long as their address is in the tree.
    ///
    /// # Vulnerability
    /// `leaf_hash()` includes only address, missing amount. Impact: unbounded
    /// claims — attacker can drain the contract by claiming more than allocated.
    pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();
        assert!(!is_claimed(&env, &claimant), "already claimed");

        // ❌ VULNERABLE: amount is not part of the proof verification
        verify_merkle_proof(&env, &claimant, &proof);

        mark_claimed(&env, &claimant);

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &claimant,
            &amount,
        );

        env.events()
            .publish((symbol_short!("claim"),), (claimant, amount));
    }

    pub fn get_claimed(env: Env, address: Address) -> bool {
        is_claimed(&env, &address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::Address as _,
        token::{Client as TokenClient, StellarAssetClient},
        Address, BytesN, Env, Vec,
    };

    /// Build a two-leaf Merkle tree for allocated_amount and return (root, proof).
    /// The vulnerable leaf only includes the address, so any amount can be claimed.
    fn build_tree(
        env: &Env,
        claimant: &Address,
        _allocated_amount: i128,
        other: &Address,
    ) -> (BytesN<32>, Vec<BytesN<32>>) {
        // ❌ VULNERABLE: leaf does not include amount
        let leaf0 = leaf_hash(env, claimant);
        let leaf1 = leaf_hash(env, other);
        let root = hash_pair(env, &leaf0, &leaf1);
        let mut proof = Vec::new(env);
        proof.push_back(leaf1);
        (root, proof)
    }

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env.register_stellar_asset_contract_v2(token_admin.clone()).address();

        StellarAssetClient::new(&env, &token_id).mint(&admin, &1_000_000);

        (env, token_id, admin, claimant, other)
    }

    /// Test that vulnerable path accepts inflated claim for allocated amount.
    #[test]
    fn test_vulnerable_accepts_inflated_claim() {
        let (env, token_id, admin, claimant, other) = setup();
        let allocated_amount = 100i128;
        let claimed_amount = 1000i128; // 10x inflation

        let (root, proof) = build_tree(&env, &claimant, allocated_amount, &other);

        let contract_id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &root, &token_id, &1u32);
        client.fund(&(allocated_amount * 20)); // Fund with enough to cover inflated claim

        // ❌ VULNERABLE: claim for 10x allocated amount succeeds
        client.claim(&claimant, &claimed_amount, &proof);
        assert!(client.get_claimed(&claimant));

        assert_eq!(TokenClient::new(&env, &token_id).balance(&claimant), claimed_amount);
    }

    /// Test boundary: claiming exactly one unit above allocated amount succeeds.
    #[test]
    fn test_vulnerable_accepts_boundary_overflow() {
        let (env, token_id, admin, claimant, other) = setup();
        let allocated_amount = 1000i128;
        let claimed_amount = 1001i128; // One unit over

        let (root, proof) = build_tree(&env, &claimant, allocated_amount, &other);

        let contract_id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &root, &token_id, &1u32);
        client.fund(&(allocated_amount * 10));

        // ❌ VULNERABLE: even one unit over is accepted
        client.claim(&claimant, &claimed_amount, &proof);
        assert_eq!(TokenClient::new(&env, &token_id).balance(&claimant), claimed_amount);
    }

    /// Test that secure version rejects inflated claims.
    #[test]
    #[should_panic(expected = "invalid merkle proof")]
    fn test_secure_rejects_inflated_claim() {
        use crate::secure::{SecureAirdrop, SecureAirdropClient};

        let (env, token_id, admin, claimant, other) = setup();
        let allocated_amount = 100i128;
        let claimed_amount = 1000i128;

        // Build a secure tree that includes amount in the leaf
        let leaf0 = secure::leaf_hash(&env, &claimant, allocated_amount, 1u32, &admin);
        let leaf1 = secure::leaf_hash(&env, &other, 0i128, 1u32, &admin);
        let root = secure::hash_pair(&env, &leaf0, &leaf1);
        let mut proof = Vec::new(&env);
        proof.push_back(leaf1);

        let contract_id = env.register_contract(None, SecureAirdrop);
        let client = SecureAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &root, &token_id, &1u32);
        client.fund(&allocated_amount);

        // ✅ SECURE: inflated claim is rejected
        client.claim(&claimant, &claimed_amount, &proof);
    }
}
