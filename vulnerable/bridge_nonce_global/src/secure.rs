use crate::verify_sig;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Bytes, BytesN, Env};

/// Per-chain nonce key: (src_chain, nonce).
/// Using a separate key type avoids colliding with the vulnerable DataKey.
#[contracttype]
pub enum SecureKey {
    /// ✅ Nonce scoped to (src_chain, nonce) — chains are fully isolated.
    NonceUsed(u32, u64),
    Balance(BytesN<32>),
}

#[contract]
pub struct SecureBridge;

#[contractimpl]
impl SecureBridge {
    /// SECURE: nonce replay guard is keyed by `(src_chain, nonce)`.
    /// Messages from different source chains never collide.
    pub fn process(
        env: Env,
        src_chain: u32,
        nonce: u64,
        token: BytesN<32>,
        amount: i128,
        recipient: BytesN<32>,
        sig: BytesN<32>,
    ) {
        // ✅ Per-chain nonce check.
        let nonce_key = SecureKey::NonceUsed(src_chain, nonce);
        if env
            .storage()
            .persistent()
            .get::<SecureKey, bool>(&nonce_key)
            .unwrap_or(false)
        {
            panic!("nonce already used");
        }

        let mut payload = Bytes::new(&env);
        payload.extend_from_array(&src_chain.to_be_bytes());
        payload.extend_from_array(&nonce.to_be_bytes());
        payload.append(&Bytes::from_array(&env, &token.to_array()));
        payload.extend_from_array(&amount.to_be_bytes());
        payload.append(&Bytes::from_array(&env, &recipient.to_array()));
        verify_sig(&env, &payload, &sig);

        // ✅ Mark nonce used only within this source chain's namespace.
        env.storage().persistent().set(&nonce_key, &true);

        let key = SecureKey::Balance(recipient.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));

        env.events()
            .publish((symbol_short!("processed"),), (src_chain, nonce, amount, recipient));
    }

    pub fn balance(env: Env, recipient: BytesN<32>) -> i128 {
        env.storage()
            .persistent()
            .get(&SecureKey::Balance(recipient))
            .unwrap_or(0)
    }

    pub fn is_nonce_used(env: Env, src_chain: u32, nonce: u64) -> bool {
        env.storage()
            .persistent()
            .get(&SecureKey::NonceUsed(src_chain, nonce))
            .unwrap_or(false)
    }
}
