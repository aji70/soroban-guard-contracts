//! VULNERABLE: Votes Accepted After Voting Deadline
//!
//! The proposal stores an `end_ledger`, but `vote` never checks the current
//! ledger against it. A late voter can change the outcome after voting closes.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub yes: i128,
    pub no: i128,
    pub end_ledger: u32,
}

#[contracttype]
pub enum DataKey {
    Proposal(u32),
    Voted(u32, Address),
}

fn proposal(env: &Env, id: u32) -> Proposal {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(id))
        .expect("missing proposal")
}

fn save_proposal(env: &Env, id: u32, proposal: &Proposal) {
    env.storage()
        .persistent()
        .set(&DataKey::Proposal(id), proposal);
}

fn voted(env: &Env, id: u32, voter: &Address) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::Voted(id, voter.clone()))
        .unwrap_or(false)
}

fn mark_voted(env: &Env, id: u32, voter: &Address) {
    env.storage()
        .persistent()
        .set(&DataKey::Voted(id, voter.clone()), &true);
}

#[contract]
pub struct VoteAfterDeadline;

#[contractimpl]
impl VoteAfterDeadline {
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
        // VULNERABLE: missing `env.ledger().sequence() <= proposal.end_ledger`.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::{SecureVoteAfterDeadline, SecureVoteAfterDeadlineClient};
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        Address, Env,
    };

    #[test]
    fn vulnerable_late_vote_changes_result_after_deadline() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(10);

        let id = env.register_contract(None, VoteAfterDeadline);
        let client = VoteAfterDeadlineClient::new(&env, &id);
        let early = Address::generate(&env);
        let late = Address::generate(&env);

        client.create(&1, &20);
        client.vote(&1, &early, &false, &10);
        env.ledger().set_sequence_number(21);
        client.vote(&1, &late, &true, &11);

        assert_eq!(client.tally(&1), (11, 10, 20));
    }

    #[test]
    fn secure_allows_exact_end_ledger() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(20);

        let id = env.register_contract(None, SecureVoteAfterDeadline);
        let client = SecureVoteAfterDeadlineClient::new(&env, &id);
        let voter = Address::generate(&env);

        client.create(&1, &20);
        client.vote(&1, &voter, &true, &1);

        assert_eq!(client.tally(&1), (1, 0, 20));
    }

    #[test]
    #[should_panic(expected = "voting closed")]
    fn secure_rejects_late_vote() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(10);

        let id = env.register_contract(None, SecureVoteAfterDeadline);
        let client = SecureVoteAfterDeadlineClient::new(&env, &id);
        let voter = Address::generate(&env);

        client.create(&1, &20);
        env.ledger().set_sequence_number(21);
        client.vote(&1, &voter, &true, &1);
    }
}
