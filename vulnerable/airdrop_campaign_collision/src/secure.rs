//! SECURE: Airdrop Campaign ID Included in Claim Tracking
//!
//! Keys claimed storage by `(campaign_id, claimant)` and includes campaign ID
//! in Merkle proof leaves.

use super::{hash_pair, DataKey};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Vec,
};

#[contracttype]
pub struct ClaimKey(pub u32, pub Address);

pub fn leaf_hash(
    env: &Env,
    campaign_id: u32,
    claimant: &Address,
    amount: i128,
) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.extend_from_array(&campaign_id.to_be_bytes());
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    env.crypto().sha256(&data).into()
}

pub fn build_tree(
    env: &Env,
    campaign_id: u32,
    claimant: &Address,
    amount: i128,
    other: &soroban_sdk::Address,
) -> (BytesN<32>, Vec<BytesN<32>>) {
    let leaf0 = leaf_hash(env, campaign_id, claimant, amount);
    let leaf1 = leaf_hash(env, campaign_id, other, 0i128);
    let root = hash_pair(env, &leaf0, &leaf1);
    let mut proof = Vec::new(env);
    proof.push_back(leaf1);
    (root, proof)
}

#[contract]
pub struct SecureAirdrop;

#[contractimpl]
impl SecureAirdrop {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn create_campaign(env: Env, campaign_id: u32, merkle_root: BytesN<32>) {
        Self::require_admin_auth(&env);
        env.storage()
            .persistent()
            .set(&DataKey::CampaignRoot(campaign_id), &merkle_root);
    }

    /// ✅ Claimed flag is scoped to campaign and leaf hash includes campaign ID.
    pub fn claim(
        env: Env,
        campaign_id: u32,
        claimant: Address,
        amount: i128,
        proof: Vec<BytesN<32>>,
    ) {
        claimant.require_auth();
        let claimed_key = ClaimKey(campaign_id, claimant.clone());
        assert!(
            !env.storage()
                .persistent()
                .get(&claimed_key)
                .unwrap_or(false),
            "already claimed"
        );

        let root: BytesN<32> = env
            .storage()
            .persistent()
            .get(&DataKey::CampaignRoot(campaign_id))
            .expect("campaign not found");
        verify_merkle_proof_secure(&env, campaign_id, &claimant, amount, &proof, &root);

        env.storage().persistent().set(&claimed_key, &true);
        env.events().publish(
            (symbol_short!("claim"), campaign_id),
            (claimant, amount),
        );
    }

    pub fn is_claimed(env: Env, campaign_id: u32, claimant: Address) -> bool {
        env.storage()
            .persistent()
            .get(&ClaimKey(campaign_id, claimant))
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

fn verify_merkle_proof_secure(
    env: &Env,
    campaign_id: u32,
    claimant: &Address,
    amount: i128,
    proof: &Vec<BytesN<32>>,
    root: &BytesN<32>,
) {
    let mut node = leaf_hash(env, campaign_id, claimant, amount);
    for sibling in proof.iter() {
        node = hash_pair(env, &node, &sibling);
    }
    assert!(node == *root, "invalid merkle proof");
}
