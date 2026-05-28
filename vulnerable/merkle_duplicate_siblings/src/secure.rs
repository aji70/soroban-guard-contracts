//! SECURE: Merkle Proof Validates Depth and Rejects Duplicate Siblings
//!
//! Stores expected tree depth at initialisation and rejects malformed proofs.

use super::fold_proof;
use soroban_sdk::{contract, contractimpl, contracttype, BytesN, Env, Vec};

#[contracttype]
pub enum SecureDataKey {
    Root,
    Depth,
}

#[contract]
pub struct SecureMerkleVerifier;

#[contractimpl]
impl SecureMerkleVerifier {
    pub fn initialize(env: Env, root: BytesN<32>, depth: u32) {
        env.storage().persistent().set(&SecureDataKey::Root, &root);
        env.storage()
            .persistent()
            .set(&SecureDataKey::Depth, &depth);
    }

    /// ✅ Enforces proof length and rejects duplicate sibling nodes.
    pub fn verify(env: Env, leaf: BytesN<32>, proof: Vec<BytesN<32>>) -> bool {
        let root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Root)
            .expect("not initialized");
        let depth: u32 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Depth)
            .expect("depth not set");

        if proof.len() as u32 != depth {
            panic!("invalid proof length");
        }

        let mut seen = Vec::new(&env);
        for sibling in proof.iter() {
            for prior in seen.iter() {
                if prior == sibling {
                    panic!("duplicate sibling");
                }
            }
            seen.push_back(sibling.clone());
        }

        fold_proof(&env, &leaf, &proof) == root
    }
}
