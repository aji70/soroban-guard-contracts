use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Bytes, BytesN, Env, Vec,
    xdr::ToXdr,
};

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
pub struct SecureAirdrop;

/// ✅ SECURE: leaf hash includes address, amount, campaign_id, and domain.
pub fn leaf_hash(
    env: &Env,
    claimant: &Address,
    amount: i128,
    campaign_id: u32,
    domain: &Address,
) -> BytesN<32> {
    let mut data = Bytes::new(env);
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    data.extend_from_array(&campaign_id.to_be_bytes());
    data.append(&domain.to_xdr(env));
    env.crypto().sha256(&data).into()
}

/// Hash two 32-byte nodes together, smaller first (canonical ordering).
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

/// ✅ SECURE: amount is verified as part of the Merkle proof.
fn verify_merkle_proof(
    env: &Env,
    claimant: &Address,
    amount: i128,
    campaign_id: u32,
    domain: &Address,
    proof: &Vec<BytesN<32>>,
) {
    let root: BytesN<32> = env
        .storage()
        .persistent()
        .get(&DataKey::MerkleRoot)
        .expect("not initialized");

    let mut node = leaf_hash(env, claimant, amount, campaign_id, domain);
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
impl SecureAirdrop {
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

    /// ✅ SECURE: claimed amount is bound to the Merkle proof.
    /// Any deviation from the allocated amount is rejected.
    pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
        claimant.require_auth();
        assert!(!is_claimed(&env, &claimant), "already claimed");

        let campaign_id: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::CampaignId)
            .unwrap_or(0);
        let domain: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Domain)
            .expect("not initialized");

        // ✅ SECURE: amount is included in proof verification
        verify_merkle_proof(&env, &claimant, amount, campaign_id, &domain, &proof);

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
