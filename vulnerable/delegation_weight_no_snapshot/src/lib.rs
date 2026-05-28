//! VULNERABLE: Delegated Voting Weight Is Not Snapshotted
//!
//! A governance contract where vote tally reads live delegated balances
//! at tally time rather than at vote time. Tokens moved or redelegated
//! after voting alter the final result.
//!
//! VULNERABILITY: `tally()` reads env.storage().persistent().get(&DELEGATED_BALANCE)
//! at execution time instead of reading a snapshot captured at vote time.

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
pub struct ProposalVul {
    pub id: u64,
    pub votes: Vec<(Address, i128, bool)>,
    pub is_finalized: bool,
}

#[contract]
pub struct GovernanceDelegationVulnerable;

#[contractimpl]
impl GovernanceDelegationVulnerable {
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

        let proposal = ProposalVul {
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

    /// Cast a vote with the current delegated balance.
    /// VULNERABLE: does not snapshot the voting power at this moment.
    pub fn vote_vulnerable(env: Env, proposal_id: u64, voter: Address, vote_yes: bool) {
        let mut proposal: ProposalVul = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        // ❌ VULNERABLE: reads current balance, not snapshot at vote time
        let voting_power = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::DelegatedBalance(voter.clone()))
            .unwrap_or(0);

        proposal.votes.push_back((voter, voting_power, vote_yes));

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
    }

    /// VULNERABLE: Tally reads live delegated balances at tally time.
    /// If delegations changed after voting, the tally reflects current state, not vote-time state.
    pub fn tally_vulnerable(env: Env, proposal_id: u64) -> bool {
        let mut proposal: ProposalVul = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        let mut yes_votes: i128 = 0;
        let mut no_votes: i128 = 0;

        for (voter, _stored_amount, vote_yes) in proposal.votes.iter() {
            // ❌ VULNERABLE: reads current balance instead of using stored vote amount
            let current_balance = env
                .storage()
                .persistent()
                .get::<_, i128>(&DataKey::DelegatedBalance(voter.clone()))
                .unwrap_or(0);

            if vote_yes {
                yes_votes += current_balance;
            } else {
                no_votes += current_balance;
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
    pub fn proposal(env: Env, proposal_id: u64) -> ProposalVul {
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
    fn test_vulnerable_tally_reflects_current_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceDelegationVulnerable);
        let client = GovernanceDelegationVulnerableClient::new(&env, &contract_id);

        client.init();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.set_delegated_balance(&alice, &100);
        client.set_delegated_balance(&bob, &50);

        let proposal_id = client.create_proposal();

        client.vote_vulnerable(&proposal_id, &alice, &true);
        client.vote_vulnerable(&proposal_id, &bob, &false);

        assert!(client.tally_vulnerable(&proposal_id));
    }

    #[test]
    fn test_vulnerable_outcome_flips_after_redelegate() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceDelegationVulnerable);
        let client = GovernanceDelegationVulnerableClient::new(&env, &contract_id);

        client.init();

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.set_delegated_balance(&alice, &100);
        client.set_delegated_balance(&bob, &50);

        let proposal_id = client.create_proposal();

        client.vote_vulnerable(&proposal_id, &alice, &true);
        client.vote_vulnerable(&proposal_id, &bob, &false);

        client.set_delegated_balance(&alice, &30);
        client.set_delegated_balance(&bob, &150);

        let result = client.tally_vulnerable(&proposal_id);
        assert!(!result);
    }

    #[test]
    fn test_vulnerable_outcome_flips_after_partial_transfer() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceDelegationVulnerable);
        let client = GovernanceDelegationVulnerableClient::new(&env, &contract_id);

        client.init();

        let alice = Address::generate(&env);

        client.set_delegated_balance(&alice, &100);

        let proposal_id = client.create_proposal();

        client.vote_vulnerable(&proposal_id, &alice, &true);

        client.set_delegated_balance(&alice, &10);

        let result = client.tally_vulnerable(&proposal_id);
        assert!(result);
    }
}
