//! VULNERABLE: Merkle Proof Accepts Duplicate Sibling Nodes
//!
//! A Merkle verifier that folds sibling lists without validating proof shape,
//! allowing malformed proofs with repeated siblings to verify.
//!
//! VULNERABILITY: no depth check, no duplicate detection, no length enforcement.
//!
//! SECURE MIRROR: `secure::SecureMerkleVerifier` stores expected tree depth,
//! rejects proofs whose length does not match, and rejects duplicate siblings.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Bytes, BytesN, Env, Vec};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Root,
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

pub fn fold_proof(env: &Env, leaf: &BytesN<32>, proof: &Vec<BytesN<32>>) -> BytesN<32> {
    let mut node = leaf.clone();
    for sibling in proof.iter() {
        node = hash_pair(env, &node, &sibling);
    }
    node
}

#[contract]
pub struct VulnerableMerkleVerifier;

#[contractimpl]
impl VulnerableMerkleVerifier {
    pub fn initialize(env: Env, root: BytesN<32>) {
        env.storage().persistent().set(&DataKey::Root, &root);
    }

    /// VULNERABLE: folds siblings with no depth or duplicate validation.
    pub fn verify(env: Env, leaf: BytesN<32>, proof: Vec<BytesN<32>>) -> bool {
        let root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::Root)
            .expect("not initialized");
        // ❌ Missing: proof length check, duplicate sibling detection.
        fold_proof(&env, &leaf, &proof) == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{BytesN, Env, Vec};

    fn leaf(env: &Env, byte: u8) -> BytesN<32> {
        BytesN::from_array(env, &[byte; 32])
    }

    fn build_depth_two_tree(env: &Env) -> (BytesN<32>, BytesN<32>, Vec<BytesN<32>>) {
        let leaf_a = leaf(env, 0x01);
        let leaf_b = leaf(env, 0x02);
        let leaf_c = leaf(env, 0x03);
        let leaf_d = leaf(env, 0x04);

        let level1_left = hash_pair(env, &leaf_a, &leaf_b);
        let level1_right = hash_pair(env, &leaf_c, &leaf_d);
        let root = hash_pair(env, &level1_left, &level1_right);

        let mut proof = Vec::new(env);
        proof.push_back(leaf_b.clone());
        proof.push_back(level1_right.clone());

        (root, leaf_a, proof)
    }

    #[test]
    fn test_well_formed_proof_accepted() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMerkleVerifier);
        let client = VulnerableMerkleVerifierClient::new(&env, &id);
        let (root, leaf_a, proof) = build_depth_two_tree(&env);
        client.initialize(&root);
        assert!(client.verify(&leaf_a, &proof));
    }

    #[test]
    fn test_duplicate_sibling_proof_accepted() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMerkleVerifier);
        let client = VulnerableMerkleVerifierClient::new(&env, &id);
        let leaf_a = leaf(&env, 0x01);
        let sibling = leaf(&env, 0x02);
        let once = hash_pair(&env, &leaf_a, &sibling);
        let root = hash_pair(&env, &once, &sibling);

        let mut proof = Vec::new(&env);
        proof.push_back(sibling.clone());
        proof.push_back(sibling);

        client.initialize(&root);
        assert!(
            client.verify(&leaf_a, &proof),
            "vulnerable path accepts proof with repeated sibling"
        );
    }

    #[test]
    fn test_secure_well_formed_proof_accepted() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMerkleVerifier);
        let client = secure::SecureMerkleVerifierClient::new(&env, &id);
        let (root, leaf_a, proof) = build_depth_two_tree(&env);
        client.initialize(&root, &2u32);
        assert!(client.verify(&leaf_a, &proof));
    }

    #[test]
    #[should_panic(expected = "duplicate sibling")]
    fn test_secure_rejects_duplicate_sibling_proof() {
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMerkleVerifier);
        let client = secure::SecureMerkleVerifierClient::new(&env, &id);
        let leaf_a = leaf(&env, 0x01);
        let sibling = leaf(&env, 0x02);
        let once = hash_pair(&env, &leaf_a, &sibling);
        let root = hash_pair(&env, &once, &sibling);

        let mut proof = Vec::new(&env);
        proof.push_back(sibling.clone());
        proof.push_back(sibling);

        client.initialize(&root, &2u32);
        client.verify(&leaf_a, &proof);
    }
}
