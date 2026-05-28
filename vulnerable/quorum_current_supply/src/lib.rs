//! VULNERABLE: Governance Quorum Uses Current Supply Instead of Snapshot
//!
//! A governance contract that computes quorum threshold by reading the live total
//! supply at tally time instead of snapshotting it when the proposal is created.
//! This allows post-voting supply mutations to retroactively flip the quorum outcome.
//!
//! VULNERABILITY: `tally()` reads env.storage().persistent().get(&TOTAL_SUPPLY)
//! at execution time, not from a snapshot taken at proposal creation.

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
pub struct Proposal {
    pub id: u64,
    pub yes_votes: i128,
    pub no_votes: i128,
    pub is_finalized: bool,
}

#[contract]
pub struct GovernanceVulnerable;

#[contractimpl]
impl GovernanceVulnerable {
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

    /// Create a proposal with the given vote counts (for testing).
    /// VULNERABLE: the total supply is NOT snapshotted here.
    pub fn create_proposal(env: Env) -> u64 {
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextProposalId)
            .unwrap_or(0);

        let proposal = Proposal {
            id,
            yes_votes: 0,
            no_votes: 0,
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

    /// Cast a vote on a proposal.
    pub fn vote(env: Env, proposal_id: u64, vote_yes: bool, amount: i128) {
        let mut proposal: Proposal = env
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

    /// VULNERABLE: Tally reads current total supply, not the snapshot from creation time.
    /// Quorum threshold = 50% of total supply at tally time.
    /// This allows post-voting supply mutations to flip the outcome.
    pub fn tally_vulnerable(env: Env, proposal_id: u64) -> bool {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("Proposal not found");

        let current_supply = env
            .storage()
            .persistent()
            .get::<_, i128>(&DataKey::TotalSupply)
            .unwrap_or(0);

        // ❌ VULNERABLE: uses current supply instead of snapshot
        let quorum_threshold = current_supply / 2;
        let total_votes = proposal.yes_votes + proposal.no_votes;

        let passes = total_votes >= quorum_threshold && proposal.yes_votes > proposal.no_votes;
        proposal.is_finalized = true;

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        passes
    }

    /// Get proposal details.
    pub fn proposal(env: Env, proposal_id: u64) -> Proposal {
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
    fn test_vulnerable_quorum_flips_after_supply_change() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceVulnerable);
        let client = GovernanceVulnerableClient::new(&env, &contract_id);

        client.init(&1000);

        let proposal_id = client.create_proposal();

        client.vote(&proposal_id, &true, &600);

        assert_eq!(client.total_supply(), 1000);
        assert!(client.tally_vulnerable(&proposal_id));

        let prop = client.proposal(&proposal_id);
        assert!(prop.is_finalized);
    }

    #[test]
    fn test_vulnerable_quorum_flips_after_mint() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceVulnerable);
        let client = GovernanceVulnerableClient::new(&env, &contract_id);

        client.init(&1000);

        let proposal_id = client.create_proposal();

        client.vote(&proposal_id, &true, &600);

        let current_supply = client.total_supply();
        assert_eq!(current_supply, 1000);

        client.mint(&1000);

        let supply_after_mint = client.total_supply();
        assert_eq!(supply_after_mint, 2000);

        let proposal_id_2 = client.create_proposal();
        client.vote(&proposal_id_2, &true, &600);

        let result = client.tally_vulnerable(&proposal_id_2);
        assert!(!result);
    }

    #[test]
    fn test_vulnerable_outcome_changes_after_burn() {
        let env = Env::default();
        let contract_id = env.register_contract(None, GovernanceVulnerable);
        let client = GovernanceVulnerableClient::new(&env, &contract_id);

        client.init(&2000);

        let proposal_id = client.create_proposal();

        client.vote(&proposal_id, &true, &1500);

        let supply_before = client.total_supply();
        assert_eq!(supply_before, 2000);

        client.burn(&1000);

        let proposal_id_2 = client.create_proposal();

        client.vote(&proposal_id_2, &true, &700);

        assert_eq!(client.total_supply(), 1000);
        let result = client.tally_vulnerable(&proposal_id_2);
        assert!(result);
    }
}
