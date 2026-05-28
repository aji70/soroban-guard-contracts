//! SECURE: Governance Quorum Uses Snapshotted Supply
//!
//! Fixed version that snapshots the total supply when the proposal is created
//! and always uses that immutable snapshot for quorum calculations.
//! Supply mutations after voting no longer affect the quorum outcome.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

#[contracttype]
pub enum DataKey {
    TotalSupply,
    NextProposalId,
    Proposal(u64),
}

#[contracttype]
#[derive(Clone)]
pub struct ProposalSecure {
    pub id: u64,
    pub yes_votes: i128,
    pub no_votes: i128,
    pub is_finalized: bool,
    pub snapshot_supply: i128,
}

#[contract]
pub struct GovernanceSecure;

#[contractimpl]
impl GovernanceSecure {
    /// Initialize with total supply.
    pub fn init(env: Env, total_supply: i128) {
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &total_supply);
        env.storage()
            .persistent()
            .set(&DataKey::NextProposalId, &1u64);
    }

    /// Mint tokens (increases total supply).
    pub fn mint(env: Env, amount: i128) {
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(current + amount));
    }

    /// Burn tokens (decreases total supply).
    pub fn burn(env: Env, amount: i128) {
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &(current - amount));
    }

    /// Get current total supply.
    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    /// Create a proposal and SNAPSHOT the current total supply.
    /// ✓ FIXED: supply is snapshotted here and stored with the proposal.
    pub fn create_proposal(env: Env) -> u64 {
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextProposalId)
            .unwrap_or(0);

        let current_supply = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::TotalSupply)
            .unwrap_or(0);

        let proposal = ProposalSecure {
            id,
            yes_votes: 0,
            no_votes: 0,
            is_finalized: false,
            snapshot_supply: current_supply,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);

        env.storage()
            .persistent()
            .set(&DataKey::NextProposalId, &(id + 1));

        id
    }

    /// Cast a vote on a proposal.
    pub fn vote(env: Env, proposal_id: u64, vote_yes: bool, amount: i128) {
        let mut proposal: ProposalSecure = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        if vote_yes {
            proposal.yes_votes += amount;
        } else {
            proposal.no_votes += amount;
        }

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
    }

    /// Tally using the SNAPSHOTTED supply, not the current supply.
    /// ✓ FIXED: always uses snapshot_supply, immune to post-voting mutations.
    pub fn tally_secure(env: Env, proposal_id: u64) -> bool {
        let mut proposal: ProposalSecure = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        // ✓ FIXED: uses snapshot_supply, not current supply
        let quorum_threshold = proposal.snapshot_supply / 2;
        let total_votes = proposal.yes_votes + proposal.no_votes;

        let passes = total_votes >= quorum_threshold && proposal.yes_votes > proposal.no_votes;
        proposal.is_finalized = true;

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        passes
    }

    /// Get proposal details.
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
    fn test_secure_quorum_immune_to_mint() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceSecure);
        let client = GovernanceSecureClient::new(&env, &contract_id);

        client.init(&1000);

        let proposal_id = client.create_proposal();

        client.vote(&proposal_id, &true, &600);

        let prop = client.proposal(&proposal_id);
        assert_eq!(prop.snapshot_supply, 1000);

        client.mint(&1000);
        assert_eq!(client.total_supply(), 2000);

        let result = client.tally_secure(&proposal_id);
        assert!(result);

        assert_eq!(client.total_supply(), 2000);
    }

    #[test]
    fn test_secure_quorum_immune_to_burn() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceSecure);
        let client = GovernanceSecureClient::new(&env, &contract_id);

        client.init(&2000);

        let proposal_id = client.create_proposal();

        client.vote(&proposal_id, &true, &1500);
        client.vote(&proposal_id, &false, &100);

        let prop = client.proposal(&proposal_id);
        assert_eq!(prop.snapshot_supply, 2000);

        client.burn(&1500);
        assert_eq!(client.total_supply(), 500);

        let result = client.tally_secure(&proposal_id);
        assert!(result);

        assert_eq!(client.total_supply(), 500);
    }

    #[test]
    fn test_secure_multiple_proposals_independent_snapshots() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceSecure);
        let client = GovernanceSecureClient::new(&env, &contract_id);

        client.init(&1000);

        let proposal_id_1 = client.create_proposal();
        client.vote(&proposal_id_1, &true, &600);

        client.mint(&1000);

        let proposal_id_2 = client.create_proposal();
        client.vote(&proposal_id_2, &true, &900);

        let result_1 = client.tally_secure(&proposal_id_1);
        assert!(result_1);

        let result_2 = client.tally_secure(&proposal_id_2);
        assert!(!result_2);
    }
}
