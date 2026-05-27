//! VULNERABLE: Airdrop Campaign ID Omitted from Claim Tracking
//!
//! A multi-campaign airdrop that keys claimed storage only by claimant address,
//! so claiming campaign A marks campaign B as claimed for the same address.
//!
//! VULNERABILITY: storage key is `(claimant_address,)` only.
//!
//! SECURE MIRROR: `secure::SecureAirdrop` keys claims by `(campaign_id, claimant)`.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env,
    Vec,
};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    CampaignRoot(u32),
    Claimed(Address),
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

    /// VULNERABLE: claimed flag is keyed only by claimant, not campaign.
    pub fn claim(
        env: Env,
        campaign_id: u32,
        claimant: Address,
        amount: i128,
        proof: Vec<BytesN<32>>,
    ) {
        claimant.require_auth();
        // ❌ Missing campaign_id in storage key — cross-campaign collision.
        let claimed_key = DataKey::Claimed(claimant.clone());
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
        verify_merkle_proof(&env, &claimant, amount, &proof, &root);

        env.storage().persistent().set(&claimed_key, &true);
        env.events().publish(
            (symbol_short!("claim"), campaign_id),
            (claimant, amount),
        );
    }

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
    use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

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

    fn setup_campaigns(
        env: &Env,
        client: &VulnerableAirdropClient,
        admin: &Address,
        claimant: &Address,
    ) -> (Vec<BytesN<32>>, Vec<BytesN<32>>) {
        let other_a = Address::generate(env);
        let other_b = Address::generate(env);
        let (root_a, proof_a) = build_tree(env, claimant, 500, &other_a);
        let (root_b, proof_b) = build_tree(env, claimant, 700, &other_b);
        client.initialize(admin);
        client.create_campaign(&1, &root_a);
        client.create_campaign(&2, &root_b);
        (proof_a, proof_b)
    }

    #[test]
    fn test_claiming_campaign_a_blocks_campaign_b() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let (proof_a, proof_b) = setup_campaigns(&env, &client, &admin, &claimant);

        client.claim(&1, &claimant, &500, &proof_a);
        assert!(client.is_claimed(&claimant));

        let second = client.try_claim(&2, &claimant, &700, &proof_b);
        assert!(second.is_err(), "campaign B blocked by shared claimed state");
    }

    #[test]
    fn test_campaigns_share_claimed_state() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);
        let (proof_a, _proof_b) = setup_campaigns(&env, &client, &admin, &claimant);

        assert!(!client.is_claimed(&claimant));
        client.claim(&1, &claimant, &500, &proof_a);
        assert!(
            client.is_claimed(&claimant),
            "single claimed flag shared across campaigns"
        );
    }

    #[test]
    fn test_secure_campaigns_isolated() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureAirdrop);
        let client = secure::SecureAirdropClient::new(&env, &id);
        let admin = Address::generate(&env);
        let claimant = Address::generate(&env);

        let other_a = Address::generate(&env);
        let other_b = Address::generate(&env);
        let (root_a, proof_a) = secure::build_tree(&env, 1, &claimant, 500, &other_a);
        let (root_b, proof_b) = secure::build_tree(&env, 2, &claimant, 700, &other_b);

        client.initialize(&admin);
        client.create_campaign(&1, &root_a);
        client.create_campaign(&2, &root_b);

        client.claim(&1, &claimant, &500, &proof_a);
        client.claim(&2, &claimant, &700, &proof_b);
        assert!(client.is_claimed(&1, &claimant));
        assert!(client.is_claimed(&2, &claimant));
    }
}
