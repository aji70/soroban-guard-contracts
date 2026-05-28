//! SECURE: Delegated Voting Weight Is Snapshotted
//!
//! Fixed version that snapshots voting power at the time the vote is cast
//! and the tally uses only those immutable recorded weights.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    DelegatedBalance(Address),
    NextProposalId,
    Proposal(u64),
}

#[contracttype]
#[derive(Clone)]
pub struct Vote {
    pub voter: Address,
    pub snapshotted_power: i128,
    pub vote_yes: bool,
}

#[contracttype]
#[derive(Clone)]
pub struct ProposalSecure {
    pub id: u64,
    pub votes: Vec<Vote>,
    pub is_finalized: bool,
}

#[contract]
pub struct GovernanceDelegationSecure;

#[contractimpl]
impl GovernanceDelegationSecure {
    /// Initialize.
    pub fn init(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::NextProposalId, &1u64);
    }

    /// Set delegated voting balance for an address.
    pub fn set_delegated_balance(env: Env, address: Address, amount: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::DelegatedBalance(address), &amount);
    }

    /// Get delegated balance for an address.
    pub fn get_delegated_balance(env: Env, address: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::DelegatedBalance(address))
            .unwrap_or(0)
    }

    /// Create a proposal.
    pub fn create_proposal(env: Env) -> u64 {
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextProposalId)
            .unwrap_or(0);

        let proposal = ProposalSecure {
            id,
            votes: Vec::new(&env),
            is_finalized: false,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);

        env.storage()
            .persistent()
            .set(&DataKey::NextProposalId, &(id + 1));

        id
    }

    /// Cast a vote and SNAPSHOT the voting power at this moment.
    /// ✓ FIXED: voting power is captured and stored with the vote.
    pub fn vote_secure(env: Env, proposal_id: u64, voter: Address, vote_yes: bool) {
        let mut proposal: ProposalSecure = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        let snapshotted_power = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::DelegatedBalance(voter.clone()))
            .unwrap_or(0);

        let vote = Vote {
            voter,
            snapshotted_power,
            vote_yes,
        };

        proposal.votes.push_back(vote);

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
    }

    /// Tally using the SNAPSHOTTED voting weights.
    /// ✓ FIXED: uses snapshotted_power from each vote, immune to post-vote changes.
    pub fn tally_secure(env: Env, proposal_id: u64) -> bool {
        let mut proposal: ProposalSecure = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        let mut yes_votes: i128 = 0;
        let mut no_votes: i128 = 0;

        for vote in proposal.votes.iter() {
            if *vote.vote_yes {
                yes_votes += vote.snapshotted_power;
            } else {
                no_votes += vote.snapshotted_power;
            }
        }

        let passes = yes_votes > no_votes;
        proposal.is_finalized = true;

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        passes
    }

    /// Get proposal.
    pub fn proposal(env: Env, proposal_id: u64) -> ProposalSecure {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_secure_tally_immune_to_balance_changes() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceDelegationSecure);
        let client = GovernanceDelegationSecureClient::new(&env, &contract_id);

        client.init();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.set_delegated_balance(&alice, &100);
        client.set_delegated_balance(&bob, &50);

        let proposal_id = client.create_proposal();

        client.vote_secure(&proposal_id, &alice, &true);
        client.vote_secure(&proposal_id, &bob, &false);

        client.set_delegated_balance(&alice, &10);
        client.set_delegated_balance(&bob, &200);

        let result = client.tally_secure(&proposal_id);
        assert!(result);
    }

    #[test]
    fn test_secure_outcome_unchanged_after_redelegate() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceDelegationSecure);
        let client = GovernanceDelegationSecureClient::new(&env, &contract_id);

        client.init();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.set_delegated_balance(&alice, &100);
        client.set_delegated_balance(&bob, &50);

        let proposal_id = client.create_proposal();

        client.vote_secure(&proposal_id, &alice, &true);
        client.vote_secure(&proposal_id, &bob, &false);

        client.set_delegated_balance(&alice, &30);
        client.set_delegated_balance(&bob, &150);

        let result = client.tally_secure(&proposal_id);
        assert!(result);
    }

    #[test]
    fn test_secure_vote_weight_preserved() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceDelegationSecure);
        let client = GovernanceDelegationSecureClient::new(&env, &contract_id);

        client.init();

        let alice = Address::generate(&env);

        client.set_delegated_balance(&alice, &100);

        let proposal_id = client.create_proposal();

        client.vote_secure(&proposal_id, &alice, &true);

        let prop = client.proposal(&proposal_id);
        assert_eq!(prop.votes.get(0).snapshotted_power, 100);

        client.set_delegated_balance(&alice, &0);

        let result = client.tally_secure(&proposal_id);
        assert!(result);

        assert_eq!(client.get_delegated_balance(&alice), 0);
    }
}
