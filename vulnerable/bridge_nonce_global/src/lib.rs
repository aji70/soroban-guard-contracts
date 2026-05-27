//! VULNERABLE: Bridge Nonce Tracked Globally Instead of Per Source Chain
//!
//! The bridge stores processed nonces in a flat global set keyed only by
//! the nonce value. Messages from different source chains share the same
//! nonce namespace. If chain A and chain B both issue nonce 7, whichever
//! arrives second is silently rejected — a valid withdrawal is blocked.
//! Conversely, a nonce collision can be exploited to suppress a legitimate
//! message by pre-spending its nonce from a different chain.
//!
//! VULNERABILITY: `DataKey::NonceUsed(nonce)` omits the source chain id,
//! so nonces from distinct chains collide.
//!
//! SECURE MIRROR: `secure::SecureBridge` keys nonces as
//! `(src_chain, emitting_bridge, nonce)`, fully isolating each chain's
//! replay-protection namespace.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Bytes, BytesN, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub fn verify_sig(env: &Env, payload: &Bytes, sig: &BytesN<32>) {
    let expected: BytesN<32> = env.crypto().sha256(payload).into();
    if expected != *sig {
        panic!("invalid signature");
    }
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// VULNERABLE: keyed only by nonce — no source chain.
    NonceUsed(u64),
    /// Per-recipient minted balance.
    Balance(BytesN<32>),
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableBridge;

#[contractimpl]
impl VulnerableBridge {
    /// VULNERABLE: nonce replay guard uses a global key that ignores source chain.
    ///
    /// # Vulnerability
    /// `DataKey::NonceUsed(nonce)` collides across source chains.
    /// Impact: nonce 7 from chain B blocks nonce 7 from chain A (or vice versa).
    pub fn process(
        env: Env,
        src_chain: u32,
        nonce: u64,
        token: BytesN<32>,
        amount: i128,
        recipient: BytesN<32>,
        sig: BytesN<32>,
    ) {
        // ❌ Global nonce key — src_chain is ignored in the replay guard.
        if env
            .storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::NonceUsed(nonce))
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

        // ❌ Marks nonce globally — blocks the same nonce from any other chain.
        env.storage()
            .persistent()
            .set(&DataKey::NonceUsed(nonce), &true);

        let key = DataKey::Balance(recipient.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));

        env.events()
            .publish((symbol_short!("processed"),), (src_chain, nonce, amount, recipient));
    }

    pub fn balance(env: Env, recipient: BytesN<32>) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(recipient))
            .unwrap_or(0)
    }

    pub fn is_nonce_used(env: Env, nonce: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::NonceUsed(nonce))
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{Bytes, BytesN, Env};

    fn make_recipient(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    fn make_token(env: &Env) -> BytesN<32> {
        BytesN::from_array(env, &[0xBB; 32])
    }

    fn sign(env: &Env, src_chain: u32, nonce: u64, token: &BytesN<32>, amount: i128, recipient: &BytesN<32>) -> BytesN<32> {
        let mut payload = Bytes::new(env);
        payload.extend_from_array(&src_chain.to_be_bytes());
        payload.extend_from_array(&nonce.to_be_bytes());
        payload.append(&Bytes::from_array(env, &token.to_array()));
        payload.extend_from_array(&amount.to_be_bytes());
        payload.append(&Bytes::from_array(env, &recipient.to_array()));
        env.crypto().sha256(&payload).into()
    }

    /// Vulnerable path: nonce 7 from chain A blocks nonce 7 from chain B.
    #[test]
    fn test_vulnerable_global_nonce_blocks_second_chain() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableBridge);
        let client = VulnerableBridgeClient::new(&env, &id);

        let chain_a = 1u32;
        let chain_b = 2u32;
        let nonce = 7u64;
        let token = make_token(&env);
        let recipient_a = make_recipient(&env, 0x0A);
        let recipient_b = make_recipient(&env, 0x0B);

        // Chain A processes nonce 7 — succeeds.
        let sig_a = sign(&env, chain_a, nonce, &token, 500, &recipient_a);
        client.process(&chain_a, &nonce, &token, &500, &recipient_a, &sig_a);
        assert_eq!(client.balance(&recipient_a), 500);

        // Chain B also has a valid nonce 7 — should succeed but is blocked.
        let sig_b = sign(&env, chain_b, nonce, &token, 300, &recipient_b);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.process(&chain_b, &nonce, &token, &300, &recipient_b, &sig_b);
        }));
        assert!(result.is_err(), "vulnerable: chain B nonce 7 incorrectly blocked");
        assert_eq!(client.balance(&recipient_b), 0, "chain B recipient received nothing");
    }

    /// Boundary: same chain, same nonce is correctly rejected (replay).
    #[test]
    fn test_same_chain_same_nonce_rejected() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableBridge);
        let client = VulnerableBridgeClient::new(&env, &id);

        let chain_a = 1u32;
        let nonce = 7u64;
        let token = make_token(&env);
        let recipient = make_recipient(&env, 0x01);
        let sig = sign(&env, chain_a, nonce, &token, 500, &recipient);

        client.process(&chain_a, &nonce, &token, &500, &recipient, &sig);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.process(&chain_a, &nonce, &token, &500, &recipient, &sig);
        }));
        assert!(result.is_err(), "same-chain replay must be rejected");
    }

    /// Secure path: nonce 7 from chain A and nonce 7 from chain B are independent.
    #[test]
    fn test_secure_isolates_nonces_per_chain() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureBridge);
        let client = SecureBridgeClient::new(&env, &id);

        let chain_a = 1u32;
        let chain_b = 2u32;
        let nonce = 7u64;
        let token = make_token(&env);
        let recipient_a = make_recipient(&env, 0x0A);
        let recipient_b = make_recipient(&env, 0x0B);

        let sig_a = sign(&env, chain_a, nonce, &token, 500, &recipient_a);
        client.process(&chain_a, &nonce, &token, &500, &recipient_a, &sig_a);
        assert_eq!(client.balance(&recipient_a), 500);

        // Chain B nonce 7 must succeed independently.
        let sig_b = sign(&env, chain_b, nonce, &token, 300, &recipient_b);
        client.process(&chain_b, &nonce, &token, &300, &recipient_b, &sig_b);
        assert_eq!(client.balance(&recipient_b), 300);
    }

    /// Secure path: same chain same nonce is still rejected.
    #[test]
    fn test_secure_rejects_same_chain_replay() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureBridge);
        let client = SecureBridgeClient::new(&env, &id);

        let chain_a = 1u32;
        let nonce = 7u64;
        let token = make_token(&env);
        let recipient = make_recipient(&env, 0x01);
        let sig = sign(&env, chain_a, nonce, &token, 500, &recipient);

        client.process(&chain_a, &nonce, &token, &500, &recipient, &sig);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.process(&chain_a, &nonce, &token, &500, &recipient, &sig);
        }));
        assert!(result.is_err(), "secure: same-chain replay must be rejected");
    }
}
