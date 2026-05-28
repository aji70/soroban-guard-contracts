//! VULNERABLE: Front-Running via Predictable Randomness
//!
//! A lottery contract where the winner is determined by
//! `env.ledger().sequence() % participants.len()`.
//!
//! `env.ledger().sequence()` is the current ledger sequence number. It is
//! **public information** — every node on the network knows it before a
//! transaction is included. This makes the outcome of `pick_winner` fully
//! predictable by anyone who can observe the mempool or control when their
//! transaction lands.
//!
//! ## Attack vectors
//!
//! 1. **Validator timing** — a validator who is also a participant can choose
//!    to include the `pick_winner` transaction only on the ledger where the
//!    sequence number maps to their own address.
//!
//! 2. **Participant sniping** — any participant can compute off-chain which
//!    sequence number would make them win, then submit `pick_winner` at
//!    exactly that ledger (e.g. by watching the mempool and front-running).
//!
//! 3. **Entry timing** — because `enter` records the participant list in
//!    storage, an attacker can join or leave the lottery to shift the modulus
//!    so that the winning index lands on their address.
//!
//! ## VULNERABILITY
//!
//! `pick_winner` uses `env.ledger().sequence() % participants.len()` as the
//! sole source of randomness. Ledger sequence is deterministic and known in
//! advance — it provides zero unpredictability.
//!
//! ## SECURE MIRROR
//!
//! `secure::CommitRevealLottery` implements a two-phase commit-reveal scheme:
//!
//! - **Commit phase**: each participant submits a hash of their secret nonce.
//!   No one can see others' secrets yet.
//! - **Reveal phase**: each participant reveals their nonce. The contract
//!   XORs all revealed nonces together to produce a seed that no single
//!   party could have predicted or biased without colluding with all others.
//!
//! For production use, a Verifiable Random Function (VRF) oracle (e.g.
//! Chainlink VRF on EVM chains, or an equivalent Soroban oracle) provides
//! the strongest guarantee: the randomness is provably unbiased and the
//! proof can be verified on-chain.
//!
//! ## SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, vec, Address, Env, Vec};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Ordered list of participant addresses.
    Participants,
    /// Address of the winner once pick_winner has been called.
    Winner,
}

// ── Vulnerable lottery ────────────────────────────────────────────────────────

#[contract]
pub struct WeakRandomnessLottery;

#[contractimpl]
impl WeakRandomnessLottery {
    /// Register `participant` for the lottery.
    ///
    /// Anyone can enter; duplicates are allowed (simplification for the demo).
    pub fn enter(env: Env, participant: Address) {
        participant.require_auth();
        let mut participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Participants)
            .unwrap_or(vec![&env]);
        participants.push_back(participant);
        env.storage()
            .persistent()
            .set(&DataKey::Participants, &participants);
    }

    /// Pick a winner using the current ledger sequence number as randomness.
    ///
    /// ❌ VULNERABLE: `env.ledger().sequence()` is public, deterministic, and
    ///    known before the transaction is submitted. A validator or a
    ///    well-timed participant can predict — or arrange — which index wins.
    ///
    /// # Panics
    /// Panics if no participants have entered.
    pub fn pick_winner(env: Env) -> Address {
        let participants: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Participants)
            .expect("no participants");

        assert!(!participants.is_empty(), "no participants");

        // ❌ Ledger sequence is known in advance — validators can time their
        //    entry or the pick_winner call to land on a favourable sequence.
        let idx = (env.ledger().sequence() as u32) % (participants.len() as u32);
        let winner = participants.get(idx).unwrap();

        env.storage()
            .persistent()
            .set(&DataKey::Winner, &winner);
        winner
    }

    /// Return the stored winner, or None if pick_winner has not been called.
    pub fn winner(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Winner)
    }

    /// Return the current participant list.
    pub fn participants(env: Env) -> Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::Participants)
            .unwrap_or(vec![&env])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger}, Address, Env};

    fn setup(env: &Env) -> (WeakRandomnessLotteryClient, Address, Address, Address) {
        let id = env.register_contract(None, WeakRandomnessLottery);
        let client = WeakRandomnessLotteryClient::new(env, &id);

        let alice = Address::generate(env);
        let bob   = Address::generate(env);
        let carol = Address::generate(env);

        env.mock_all_auths();
        client.enter(&alice);
        client.enter(&bob);
        client.enter(&carol);

        (client, alice, bob, carol)
    }

    /// The winner is selected deterministically from the ledger sequence.
    ///
    /// With 3 participants and sequence = 0:  idx = 0 % 3 = 0 → alice
    /// With 3 participants and sequence = 1:  idx = 1 % 3 = 1 → bob
    /// With 3 participants and sequence = 2:  idx = 2 % 3 = 2 → carol
    ///
    /// This demonstrates that the outcome is fully predictable — anyone who
    /// knows the sequence number at the time of the call knows the winner.
    #[test]
    fn test_winner_determined_by_sequence() {
        let env = Env::default();
        let (client, alice, bob, carol) = setup(&env);

        // sequence = 0 → index 0 → alice
        env.ledger().with_mut(|l| l.sequence_number = 0);
        assert_eq!(client.pick_winner(), alice);

        // Reset winner for next pick.
        env.ledger().with_mut(|l| l.sequence_number = 1);
        assert_eq!(client.pick_winner(), bob);

        env.ledger().with_mut(|l| l.sequence_number = 2);
        assert_eq!(client.pick_winner(), carol);
    }

    /// The same sequence number always picks the same winner.
    ///
    /// This is the core of the attack: an adversary can call pick_winner
    /// repeatedly (or wait for the right ledger) and always get the same
    /// deterministic result. There is no entropy — the "randomness" is
    /// entirely controlled by the ledger sequence.
    #[test]
    fn test_same_sequence_always_picks_same_winner() {
        let env = Env::default();
        let (client, _alice, bob, _carol) = setup(&env);

        // Fix the sequence at 1 → always picks bob (index 1).
        env.ledger().with_mut(|l| l.sequence_number = 1);

        let first  = client.pick_winner();
        let second = client.pick_winner();
        let third  = client.pick_winner();

        assert_eq!(first,  bob);
        assert_eq!(second, bob);
        assert_eq!(third,  bob);
    }

    /// An attacker who controls when pick_winner is called can guarantee
    /// they win by waiting for the ledger sequence where their index is
    /// selected.
    ///
    /// Here we simulate the attack: the attacker (carol, index 2) waits
    /// until sequence % 3 == 2 and then calls pick_winner.
    #[test]
    fn test_attacker_can_predict_and_time_winning_call() {
        let env = Env::default();
        let (client, _alice, _bob, carol) = setup(&env);

        // Carol is at index 2. She waits for sequence = 2 (or 5, 8, …).
        // Any sequence ≡ 2 (mod 3) will select her.
        env.ledger().with_mut(|l| l.sequence_number = 2);
        let winner = client.pick_winner();
        assert_eq!(winner, carol, "attacker timed the call to guarantee a win");
    }
}
