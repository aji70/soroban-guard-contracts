use super::{verify_sig, DataKey};
use soroban_sdk::{contract, contractimpl, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env};

#[contract]
pub struct SecureBridge;

/// Build and sign the secure payload (exposed for tests).
pub fn sign_secure(
    env: &Env,
    src_chain: u32,
    dst_chain: u32,
    bridge_id: &Address,
    nonce: u64,
    token: &BytesN<32>,
    amount: i128,
    recipient: &BytesN<32>,
) -> BytesN<32> {
    let payload = build_payload(env, src_chain, dst_chain, bridge_id, nonce, token, amount, recipient);
    env.crypto().sha256(&payload).into()
}

fn build_payload(
    env: &Env,
    src_chain: u32,
    dst_chain: u32,
    bridge_id: &Address,
    nonce: u64,
    token: &BytesN<32>,
    amount: i128,
    recipient: &BytesN<32>,
) -> Bytes {
    let mut payload = Bytes::new(env);
    payload.extend_from_array(&src_chain.to_be_bytes());
    payload.extend_from_array(&dst_chain.to_be_bytes());
    // Bind to this specific bridge contract address via its XDR bytes.
    let id_xdr = bridge_id.to_xdr(env);
    payload.append(&id_xdr);
    payload.extend_from_array(&nonce.to_be_bytes());
    payload.append(&Bytes::from_array(env, &token.to_array()));
    payload.extend_from_array(&amount.to_be_bytes());
    payload.append(&Bytes::from_array(env, &recipient.to_array()));
    payload
}

#[contractimpl]
impl SecureBridge {
    /// SECURE: payload includes src_chain, dst_chain, and this contract's id.
    /// A message signed for one chain/deployment is invalid everywhere else.
    pub fn mint(
        env: Env,
        src_chain: u32,
        dst_chain: u32,
        nonce: u64,
        token: BytesN<32>,
        amount: i128,
        recipient: BytesN<32>,
        sig: BytesN<32>,
    ) {
        if env
            .storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::NonceUsed(nonce))
            .unwrap_or(false)
        {
            panic!("nonce already used");
        }

        // ✅ Payload binds src_chain, dst_chain, and this contract's address.
        let payload = build_payload(
            &env,
            src_chain,
            dst_chain,
            &env.current_contract_address(),
            nonce,
            &token,
            amount,
            &recipient,
        );
        verify_sig(&env, &payload, &sig);

        env.storage()
            .persistent()
            .set(&DataKey::NonceUsed(nonce), &true);

        let key = DataKey::Balance(recipient.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));

        env.events().publish(
            (symbol_short!("minted"),),
            (src_chain, dst_chain, nonce, token, amount, recipient),
        );
    }

    pub fn balance(env: Env, recipient: BytesN<32>) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(recipient))
            .unwrap_or(0)
    }
}
