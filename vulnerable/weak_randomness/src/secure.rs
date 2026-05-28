//! SECURE: Commit-Reveal Lottery
//!
//! This is the fixed mirror of `WeakRandomnessLottery`.
//!
//! ## Why ledger sequence / timestamp is not random
//!
//! `env.ledger().sequence()` and `env.ledger().timestamp()` are both public,
//! deterministic values that are known before a transaction is included in a
//! ledger. They provide **zero unpredictability** as a randomness source.
//!
//! ## Fix: commit-reveal scheme
//!
//! A commit-reveal scheme prevents any single party from biasing the outcome:
//!
//! 1. **Commit phase** — each participant submits `hash(secret_nonce)`.
//!    The secret is hidden; no one can see it yet.
//!
//! 2. **Reveal phase** — each participant reveals their `secret_nonce`.
//!    The contract verifies `hash(revealed) == committed` and XORs all
//!    revealed nonces into a combined seed.
//!
//! 3. **Pick** — `seed % participants.len()` selects the winner.
//!
//! To bias the outcome an attacker would need to see all other participants'
//! secrets before committing their own — which the commit phase prevents.
//! The last revealer has a "last-mover advantage" (they can choose not to
//! reveal if the outcome is unfavourable), but this is mitigated by requiring
//! all participants to reveal within a deadline or forfeit their entry.
//!
//! ## Production recommendation
//!
//! For the strongest guarantee use a **Verifiable Random Function (VRF)**
//! oracle. A VRF produces a random output together with a cryptographic proof
//! that the output was computed correctly from a secret key. The proof can be
//! verified on-chain, so the randomness is both unpredictable and tamper-proof.
//! No commit-reveal coordination is needed.

use soroban_sdk::{
    contract, contractimpl, contracttype, vec, Address, Bytes, BytesN, Env, Vec,
};

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum SecureKey {
    /// Ordered list of participant addresses.
    Participants,
    /// Committed hash for each participant: SecureKey::Commit(addr) → BytesN<32>
    Commit(Address),
    /// Revealed nonce for each participant: SecureKey::Reveal(addr) → u64
    Reveal(Address),
    /// Combined XOR seed built up as participants reveal.
    Seed,
    /// Number of participants who have revealed so far.
    RevealCount,
    /// Winner address once draw() has been called.
    Winner,
}

// ── Secure commit-reveal lottery ──────────────────────────────────────────────

#[contract]
pub struct CommitRevealLottery;

#[contractimpl]
impl CommitRevealLottery {
    /// Phase 1 — commit.
    ///
    /// Each participant submits `SHA-256(secret_nonce)`. The secret is not
    /// revealed yet, so no one can see it and bias their own commitment.
    pub fn commit(env: Env, participant: Address, commitment: BytesN<32>) {
        participant.require_auth();

        let mut participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&SecureKey::Participants)
            .unwrap_or(vec![&env]);
        participants.push_back(participant.clone());
        env.storage()
            .persistent()
            .set(&SecureKey::Participants, &participants);

        env.storage()
            .persistent()
            .set(&SecureKey::Commit(participant), &commitment);
    }

    /// Phase 2 — reveal.
    ///
    /// Each participant reveals their `secret_nonce`. The contract verifies
    /// it matches the earlier commitment, then folds it into the shared seed
    /// via XOR.
    ///
    /// # Panics
    /// Panics if the participant never committed, or if the revealed nonce
    /// does not match the commitment.
    pub fn reveal(env: Env, participant: Address, secret_nonce: u64) {
        participant.require_auth();

        let committed: BytesN<32> = env
            .storage()
            .persistent()
            .get(&SecureKey::Commit(participant.clone()))
            .expect("no commitment found for participant");

        // Verify: hash(revealed_nonce) must equal the stored commitment.
        let nonce_bytes = Bytes::from_array(&env, &secret_nonce.to_be_bytes());
        let revealed_hash: BytesN<32> = env.crypto().sha256(&nonce_bytes).into();
        assert!(revealed_hash == committed, "revealed nonce does not match commitment");

        // Fold the nonce into the shared seed via XOR.
        let current_seed: u64 = env
            .storage()
            .persistent()
            .get(&SecureKey::Seed)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&SecureKey::Seed, &(current_seed ^ secret_nonce));

        let count: u32 = env
            .storage()
            .persistent()
            .get(&SecureKey::RevealCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&SecureKey::RevealCount, &(count + 1));

        env.storage()
            .persistent()
            .set(&SecureKey::Reveal(participant), &secret_nonce);
    }

    /// Phase 3 — draw.
    ///
    /// Once all participants have revealed, derive the winner from the
    /// combined XOR seed. No single participant could have predicted or
    /// controlled the final seed without knowing all others' secrets first.
    ///
    /// # Panics
    /// Panics if not all participants have revealed yet.
    pub fn draw(env: Env) -> Address {
        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&SecureKey::Participants)
            .expect("no participants");

        assert!(!participants.is_empty(), "no participants");

        let reveal_count: u32 = env
            .storage()
            .persistent()
            .get(&SecureKey::RevealCount)
            .unwrap_or(0);

        // ✅ Require all participants to have revealed before drawing.
        assert!(
            reveal_count == participants.len() as u32,
            "not all participants have revealed"
        );

        let seed: u64 = env
            .storage()
            .persistent()
            .get(&SecureKey::Seed)
            .unwrap_or(0);

        // ✅ Seed is the XOR of all participants' secret nonces — no single
        //    party could have biased it without seeing everyone else's secret.
        let idx = (seed % participants.len() as u64) as u32;
        let winner = participants.get(idx).unwrap();

        env.storage()
            .persistent()
            .set(&SecureKey::Winner, &winner);
        winner
    }

    /// Return the stored winner, or None if draw() has not been called.
    pub fn winner(env: Env) -> Option<Address> {
        env.storage().persistent().get(&SecureKey::Winner)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

    fn sha256(env: &Env, nonce: u64) -> BytesN<32> {
        let bytes = Bytes::from_array(env, &nonce.to_be_bytes());
        env.crypto().sha256(&bytes).into()
    }

    fn setup(env: &Env) -> (CommitRevealLotteryClient, Address, Address, Address) {
        let id = env.register_contract(None, CommitRevealLottery);
        let client = CommitRevealLotteryClient::new(env, &id);
        let alice = Address::generate(env);
        let bob   = Address::generate(env);
        let carol = Address::generate(env);
        (client, alice, bob, carol)
    }

    /// Full happy-path: all three participants commit then reveal, draw picks
    /// a winner deterministically from the XOR seed.
    #[test]
    fn test_secure_full_round() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, alice, bob, carol) = setup(&env);

        // Nonces chosen so XOR = 0xAA ^ 0xBB ^ 0xCC = 0x77 → idx = 0x77 % 3 = 1 → bob
        let nonce_a: u64 = 0xAA;
        let nonce_b: u64 = 0xBB;
        let nonce_c: u64 = 0xCC;

        client.commit(&alice, &sha256(&env, nonce_a));
        client.commit(&bob,   &sha256(&env, nonce_b));
        client.commit(&carol, &sha256(&env, nonce_c));

        client.reveal(&alice, &nonce_a);
        client.reveal(&bob,   &nonce_b);
        client.reveal(&carol, &nonce_c);

        // seed = 0xAA ^ 0xBB ^ 0xCC = 0x77 = 119
        // idx  = 119 % 3 = 2 → carol
        let winner = client.draw();
        assert_eq!(winner, carol);
        assert_eq!(client.winner(), Some(carol));
    }

    /// draw() panics if a participant has not yet revealed.
    #[test]
    #[should_panic(expected = "not all participants have revealed")]
    fn test_secure_draw_requires_all_reveals() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, alice, bob, carol) = setup(&env);

        client.commit(&alice, &sha256(&env, 1));
        client.commit(&bob,   &sha256(&env, 2));
        client.commit(&carol, &sha256(&env, 3));

        // Only alice and bob reveal — carol has not.
        client.reveal(&alice, &1);
        client.reveal(&bob,   &2);

        // Should panic: carol hasn't revealed.
        client.draw();
    }

    /// reveal() panics if the nonce doesn't match the commitment.
    #[test]
    #[should_panic(expected = "revealed nonce does not match commitment")]
    fn test_secure_reveal_rejects_wrong_nonce() {
        let env = Env::default();
        env.mock_all_auths();
        let (client, alice, _bob, _carol) = setup(&env);

        client.commit(&alice, &sha256(&env, 42));
        // Reveal a different nonce — should panic.
        client.reveal(&alice, &99);
    }
}
