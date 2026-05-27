//! VULNERABLE: Bridge Message Does Not Include Destination Chain ID
//!
//! The bridge verifies a signed mint message but the signed payload only
//! covers `(nonce, token, amount, recipient)`. The destination chain is
//! never bound into the signature. A valid message produced for chain A
//! can be replayed verbatim on chain B, minting wrapped assets on a chain
//! the originator never intended.
//!
//! VULNERABILITY: `mint` hashes and verifies a payload that omits the
//! destination chain id, so the same `(nonce, token, amount, recipient,
//! signature)` tuple is accepted by every deployment.
//!
//! SECURE MIRROR: `secure::SecureBridge` includes `src_chain`, `dst_chain`,
//! and the bridge contract id in the signed payload, binding the message
//! to exactly one destination.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Bytes, BytesN, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Simulated signature: SHA-256 of the payload bytes.
/// Stands in for an ed25519 validator signature in a real bridge.
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
    /// Tracks minted balance per recipient (simulates wrapped token ledger).
    Balance(BytesN<32>),
    /// Marks a nonce as consumed to prevent same-chain replay.
    NonceUsed(u64),
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableBridge;

#[contractimpl]
impl VulnerableBridge {
    /// VULNERABLE: mints wrapped tokens after verifying a signature over
    /// `(nonce, token, amount, recipient)` — destination chain is absent.
    ///
    /// # Vulnerability
    /// The signed payload does not bind the destination chain id.
    /// Impact: a message signed for chain A is accepted unchanged on chain B.
    pub fn mint(
        env: Env,
        nonce: u64,
        token: BytesN<32>,
        amount: i128,
        recipient: BytesN<32>,
        sig: BytesN<32>,
    ) {
        // Replay guard (same-chain only).
        if env
            .storage()
            .persistent()
            .get::<DataKey, bool>(&DataKey::NonceUsed(nonce))
            .unwrap_or(false)
        {
            panic!("nonce already used");
        }

        // ❌ Payload omits destination chain id — cross-chain replay is possible.
        let mut payload = Bytes::new(&env);
        payload.extend_from_array(&nonce.to_be_bytes());
        payload.append(&Bytes::from_array(&env, &token.to_array()));
        payload.extend_from_array(&amount.to_be_bytes());
        payload.append(&Bytes::from_array(&env, &recipient.to_array()));

        verify_sig(&env, &payload, &sig);

        env.storage()
            .persistent()
            .set(&DataKey::NonceUsed(nonce), &true);

        let key = DataKey::Balance(recipient.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));

        env.events()
            .publish((symbol_short!("minted"),), (nonce, token, amount, recipient));
    }

    pub fn balance(env: Env, recipient: BytesN<32>) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(recipient))
            .unwrap_or(0)
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
        BytesN::from_array(env, &[0xAA; 32])
    }

    /// Build the vulnerable (chain-id-free) payload and sign it.
    fn sign_vulnerable(
        env: &Env,
        nonce: u64,
        token: &BytesN<32>,
        amount: i128,
        recipient: &BytesN<32>,
    ) -> BytesN<32> {
        let mut payload = Bytes::new(env);
        payload.extend_from_array(&nonce.to_be_bytes());
        payload.append(&Bytes::from_array(env, &token.to_array()));
        payload.extend_from_array(&amount.to_be_bytes());
        payload.append(&Bytes::from_array(env, &recipient.to_array()));
        env.crypto().sha256(&payload).into()
    }

    /// Vulnerable path: same signed message mints on two separate bridge deployments.
    #[test]
    fn test_vulnerable_message_replays_across_chains() {
        let env = Env::default();

        // Two independent bridge deployments (simulating chain A and chain B).
        let bridge_a = env.register_contract(None, VulnerableBridge);
        let bridge_b = env.register_contract(None, VulnerableBridge);
        let client_a = VulnerableBridgeClient::new(&env, &bridge_a);
        let client_b = VulnerableBridgeClient::new(&env, &bridge_b);

        let nonce = 1u64;
        let token = make_token(&env);
        let amount = 1000_i128;
        let recipient = make_recipient(&env, 0x01);

        // Signature produced for chain A (no chain id in payload).
        let sig = sign_vulnerable(&env, nonce, &token, amount, &recipient);

        // Mint on chain A — intended.
        client_a.mint(&nonce, &token, &amount, &recipient, &sig);
        assert_eq!(client_a.balance(&recipient), 1000);

        // Replay the exact same message on chain B — should be rejected but isn't.
        client_b.mint(&nonce, &token, &amount, &recipient, &sig);
        assert_eq!(
            client_b.balance(&recipient),
            1000,
            "vulnerable: cross-chain replay succeeded"
        );
    }

    /// Boundary: same-chain nonce replay is blocked even in the vulnerable contract.
    #[test]
    fn test_same_chain_replay_blocked() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableBridge);
        let client = VulnerableBridgeClient::new(&env, &id);

        let nonce = 1u64;
        let token = make_token(&env);
        let amount = 500_i128;
        let recipient = make_recipient(&env, 0x02);
        let sig = sign_vulnerable(&env, nonce, &token, amount, &recipient);

        client.mint(&nonce, &token, &amount, &recipient, &sig);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.mint(&nonce, &token, &amount, &recipient, &sig);
        }));
        assert!(result.is_err(), "same-chain replay must be rejected");
    }

    /// Secure path: message signed for chain A is rejected on chain B.
    #[test]
    fn test_secure_rejects_cross_chain_replay() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();

        let chain_a = 1u32;
        let chain_b = 2u32;

        let bridge_a = env.register_contract(None, secure::SecureBridge);
        let bridge_b = env.register_contract(None, secure::SecureBridge);
        let client_a = SecureBridgeClient::new(&env, &bridge_a);
        let client_b = SecureBridgeClient::new(&env, &bridge_b);

        let nonce = 1u64;
        let token = BytesN::from_array(&env, &[0xAA; 32]);
        let amount = 1000_i128;
        let recipient = make_recipient(&env, 0x01);

        // Sign for chain A, targeting bridge_a's contract id.
        let sig_a = secure::sign_secure(
            &env, chain_a, chain_a, &bridge_a, nonce, &token, amount, &recipient,
        );

        // Mint on chain A — succeeds.
        client_a.mint(&chain_a, &chain_a, &nonce, &token, &amount, &recipient, &sig_a);
        assert_eq!(client_a.balance(&recipient), 1000);

        // Attempt to replay on chain B — must fail (different dst_chain and contract id).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client_b.mint(&chain_a, &chain_b, &nonce, &token, &amount, &recipient, &sig_a);
        }));
        assert!(
            result.is_err(),
            "secure bridge must reject cross-chain replay"
        );
        assert_eq!(
            client_b.balance(&recipient),
            0,
            "no tokens must be minted on chain B"
        );
    }

    /// Secure path: correctly signed message for chain B is accepted on chain B.
    #[test]
    fn test_secure_accepts_correctly_targeted_message() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let chain_a = 1u32;
        let chain_b = 2u32;

        let bridge_b = env.register_contract(None, secure::SecureBridge);
        let client_b = SecureBridgeClient::new(&env, &bridge_b);

        let nonce = 1u64;
        let token = BytesN::from_array(&env, &[0xAA; 32]);
        let amount = 500_i128;
        let recipient = make_recipient(&env, 0x03);

        // Sign specifically for chain B.
        let sig_b = secure::sign_secure(
            &env, chain_a, chain_b, &bridge_b, nonce, &token, amount, &recipient,
        );

        client_b.mint(&chain_a, &chain_b, &nonce, &token, &amount, &recipient, &sig_b);
        assert_eq!(client_b.balance(&recipient), 500);
    }
}
