//! SECURE: Votes after the proposal end ledger are rejected.

use super::{mark_voted, proposal, save_proposal, voted, Proposal};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVoteAfterDeadline;

#[contractimpl]
impl SecureVoteAfterDeadline {
    pub fn create(env: Env, id: u32, end_ledger: u32) {
        save_proposal(
            &env,
            id,
            &Proposal {
                yes: 0,
                no: 0,
                end_ledger,
            },
        );
    }

    pub fn vote(env: Env, id: u32, voter: Address, support: bool, weight: i128) {
        voter.require_auth();
        assert!(!voted(&env, id, &voter), "already voted");

        let mut proposal = proposal(&env, id);
        assert!(
            env.ledger().sequence() <= proposal.end_ledger,
            "voting closed"
        );

        if support {
            proposal.yes += weight;
        } else {
            proposal.no += weight;
        }
        save_proposal(&env, id, &proposal);
        mark_voted(&env, id, &voter);
    }

    pub fn tally(env: Env, id: u32) -> (i128, i128, u32) {
        let proposal = proposal(&env, id);
        (proposal.yes, proposal.no, proposal.end_ledger)
    }
}
