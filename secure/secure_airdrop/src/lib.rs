//! SECURE: Merkle-proof-based airdrop
//!
//! Eligible addresses claim tokens by supplying a Merkle proof against a root
//! stored at initialisation. One claim per address is enforced via persistent
//! storage. Only the admin can fund the pool.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Bytes, BytesN, Env, Vec,
};

#[contracttype]
pub enum DataKey {
    Admin,
    MerkleRoot,
    Token,
    Claimed(Address),
}

#[contract]
pub struct SecureAirdrop;

// ── helpers ──────────────────────────────────────────────────────────────────

fn leaf_hash(env: &Env, claimant: &Address, amount: i128) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    env.crypto().sha256(&data)
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
    env.crypto().sha256(&data)
}

fn verify_merkle_proof(
    env: &Env,
    claimant: &Address,
    amount: i128,
    proof: &Vec<BytesN<32>>,
) {
    let root: BytesN<32> = env
        .storage()
        .persistent()
        .get(&DataKey::MerkleRoot)
        .expect("not initialized");

    let mut node = leaf_hash(env, claimant, amount);
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

// ── contract ─────────────────────────────────────────────────────────────────

#[contractimpl]
impl SecureAirdrop {
    pub fn initialize(env: Env, admin: Address, merkle_root: BytesN<32>, token: Address) {
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::MerkleRoot, &merkle_root);
        env.storage().persistent().set(&DataKey::Token, &token);
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

    /// Claim tokens by providing a valid Merkle proof.
    /// Marks the address as claimed before transferring (checks-effects-interactions).
    pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();
        assert!(!is_claimed(&env, &claimant), "already claimed");
        verify_merkle_proof(&env, &claimant, amount, &proof);

        // ✅ Mark claimed BEFORE transfer (checks-effects-interactions)
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

    /// Build a two-leaf Merkle tree for `claimant` and return (root, proof).
    /// Tree:
    ///   leaf0 = hash(claimant, amount)
    ///   leaf1 = hash(other, 0)          ← dummy second leaf
    ///   root  = hash_pair(leaf0, leaf1)
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

    fn setup() -> (Env, Address, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        // Deploy a native/SAC token for testing
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let other = Address::generate(&env);

        let token_admin = Address::generate(&env);
        let token_id = env.register_stellar_asset_contract_v2(token_admin.clone()).address();

        // Mint tokens to admin so they can fund the airdrop
        StellarAssetClient::new(&env, &token_id).mint(&admin, &10_000);

        (env, token_id, admin, claimant, other)
    }

    #[test]
    fn test_valid_proof_claims_successfully() {
        let (env, token_id, admin, claimant, other) = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&env, &claimant, amount, &other);

        let contract_id = env.register_contract(None, SecureAirdrop);
        let client = SecureAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &root, &token_id);
        client.fund(&amount);

        assert!(!client.get_claimed(&claimant));
        client.claim(&claimant, &amount, &proof);
        assert!(client.get_claimed(&claimant));

        // Claimant received the tokens
        assert_eq!(TokenClient::new(&env, &token_id).balance(&claimant), amount);
    }

    #[test]
    #[should_panic(expected = "already claimed")]
    fn test_double_claim_panics() {
        let (env, token_id, admin, claimant, other) = setup();
        let amount = 500i128;

        let (root, proof) = build_tree(&env, &claimant, amount, &other);

        let contract_id = env.register_contract(None, SecureAirdrop);
        let client = SecureAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &root, &token_id);
        client.fund(&(amount * 2));

        client.claim(&claimant, &amount, &proof);
        // Second claim must panic
        client.claim(&claimant, &amount, &proof);
    }

    #[test]
    #[should_panic(expected = "invalid merkle proof")]
    fn test_invalid_proof_rejected_before_state_change() {
        let (env, token_id, admin, claimant, other) = setup();
        let amount = 500i128;

        let (root, _valid_proof) = build_tree(&env, &claimant, amount, &other);

        let contract_id = env.register_contract(None, SecureAirdrop);
        let client = SecureAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &root, &token_id);
        client.fund(&amount);

        // Construct a bogus proof
        let mut bad_proof: Vec<BytesN<32>> = Vec::new(&env);
        bad_proof.push_back(BytesN::from_array(&env, &[0u8; 32]));

        client.claim(&claimant, &amount, &bad_proof);

        // State must not have changed
        assert!(!client.get_claimed(&claimant));
    }
}
