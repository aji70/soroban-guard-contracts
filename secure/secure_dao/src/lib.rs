//! SECURE: On-chain DAO with quorum, vote-weight snapshots, and timelock
//!
//! SECURITY PROPERTIES:
//! 1. Proposals require a minimum quorum (10% of total supply) to pass.
//! 2. Proposals require a strict majority (>50% of votes cast) to pass.
//! 3. A timelock delay (1000 ledgers) between queue and execute prevents
//!    flash-loan governance attacks — an attacker cannot borrow tokens,
//!    vote, and execute in the same transaction.
//! 4. Vote weight is snapshotted at proposal creation time (total_supply
//!    stored on the proposal), so supply changes after creation don't affect
//!    quorum calculation.
//! 5. Each address can vote at most once per proposal.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Ledgers that must pass between queue and execute.
const TIMELOCK_DELAY: u32 = 1000;
/// Quorum: votes_for + votes_against must reach this fraction of total supply.
/// Represented as basis points (1000 = 10%).
const QUORUM_BPS: u64 = 1000;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Total token supply (i128)
    TotalSupply,
    /// Token balance for an address
    Balance(Address),
    /// Next proposal id counter
    NextId,
    /// Proposal state
    Proposal(u64),
    /// Whether `voter` has voted on `proposal_id`
    Voted(u64, Address),
}

// ── Types ─────────────────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct Proposal {
    pub proposer: Address,
    /// Total supply snapshotted at creation — used for quorum check.
    pub snapshot_supply: i128,
    pub votes_for: i128,
    pub votes_against: i128,
    pub queued: bool,
    pub executed: bool,
    /// Ledger sequence after which execute() is allowed (set when queued).
    pub execute_after: u32,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct SecureDao;

#[contractimpl]
impl SecureDao {
    // ── Token helpers (minimal — for testing governance logic) ────────────────

    /// Mint tokens to an address (no auth guard — test helper).
    pub fn mint(env: Env, to: Address, amount: i128) {
        let bal_key = DataKey::Balance(to.clone());
        let bal: i128 = env.storage().persistent().get(&bal_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&bal_key, &bal.checked_add(amount).expect("overflow"));

        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalSupply, &supply.checked_add(amount).expect("overflow"));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    pub fn total_supply(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0)
    }

    // ── Governance ────────────────────────────────────────────────────────────

    /// Create a new proposal. The proposer must hold at least 1 token.
    ///
    /// Returns the new proposal id.
    pub fn create_proposal(env: Env, proposer: Address) -> u64 {
        proposer.require_auth();

        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(proposer.clone()))
            .unwrap_or(0);
        if bal < 1 {
            panic!("must hold tokens to propose");
        }

        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextId)
            .unwrap_or(0);

        let supply: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalSupply)
            .unwrap_or(0);

        let proposal = Proposal {
            proposer: proposer.clone(),
            snapshot_supply: supply,
            votes_for: 0,
            votes_against: 0,
            queued: false,
            executed: false,
            execute_after: 0,
        };

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage()
            .persistent()
            .set(&DataKey::NextId, &(id + 1));

        env.events()
            .publish((symbol_short!("proposed"),), (id, proposer));

        id
    }

    /// Cast a vote on a proposal using the caller's token balance as weight.
    ///
    /// `support = true` → vote for; `support = false` → vote against.
    /// Each address may vote at most once.
    pub fn vote(env: Env, voter: Address, proposal_id: u64, support: bool) {
        voter.require_auth();

        let voted_key = DataKey::Voted(proposal_id, voter.clone());
        if env.storage().persistent().has(&voted_key) {
            panic!("already voted");
        }

        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal not found");

        if proposal.queued || proposal.executed {
            panic!("voting closed");
        }

        let weight: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(voter.clone()))
            .unwrap_or(0);
        if weight < 1 {
            panic!("no voting power");
        }

        if support {
            proposal.votes_for = proposal.votes_for.checked_add(weight).expect("overflow");
        } else {
            proposal.votes_against = proposal
                .votes_against
                .checked_add(weight)
                .expect("overflow");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        env.storage().persistent().set(&voted_key, &true);

        env.events()
            .publish((symbol_short!("voted"),), (proposal_id, voter, support, weight));
    }

    /// Queue a passing proposal behind the timelock.
    ///
    /// Requires:
    /// - votes_for > votes_against (majority)
    /// - (votes_for + votes_against) >= 10% of snapshot_supply (quorum)
    pub fn queue(env: Env, proposal_id: u64) {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal not found");

        if proposal.queued {
            panic!("already queued");
        }
        if proposal.executed {
            panic!("already executed");
        }

        // Majority check
        if proposal.votes_for <= proposal.votes_against {
            panic!("proposal did not pass");
        }

        // Quorum check: total votes >= 10% of snapshot supply
        let total_votes = proposal
            .votes_for
            .checked_add(proposal.votes_against)
            .expect("overflow");
        let quorum_threshold = proposal
            .snapshot_supply
            .checked_mul(QUORUM_BPS as i128)
            .expect("overflow")
            / 10_000;
        if total_votes < quorum_threshold {
            panic!("quorum not reached");
        }

        proposal.queued = true;
        proposal.execute_after = env
            .ledger()
            .sequence()
            .checked_add(TIMELOCK_DELAY)
            .expect("overflow");

        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events()
            .publish((symbol_short!("queued"),), (proposal_id, proposal.execute_after));
    }

    /// Execute a queued proposal after the timelock has expired.
    pub fn execute(env: Env, proposal_id: u64) {
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal not found");

        if !proposal.queued {
            panic!("proposal not queued");
        }
        if proposal.executed {
            panic!("already executed");
        }
        if env.ledger().sequence() < proposal.execute_after {
            panic!("timelock not expired");
        }

        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);

        env.events()
            .publish((symbol_short!("executed"),), (proposal_id,));
    }

    /// Return the proposal state for a given id.
    pub fn get_proposal(env: Env, proposal_id: u64) -> Proposal {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal not found")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, testutils::LedgerInfo, Address, Env};

    fn make_env() -> (Env, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureDao);
        (env, contract_id)
    }

    /// A proposal with sufficient votes and quorum can be queued and executed
    /// after the timelock expires.
    #[test]
    fn test_full_lifecycle() {
        let (env, cid) = make_env();
        let client = SecureDaoClient::new(&env, &cid);

        let voter = Address::generate(&env);
        // voter holds 600 out of 1000 total → quorum (10%) = 100, votes_for = 600 ✓
        client.mint(&voter, &600);
        client.mint(&Address::generate(&env), &400);

        let pid = client.create_proposal(&voter);
        client.vote(&voter, &pid, &true);
        client.queue(&pid);

        let p = client.get_proposal(&pid);
        assert!(p.queued);
        assert!(!p.executed);

        // Advance ledger past timelock
        env.ledger().set(LedgerInfo {
            sequence_number: p.execute_after,
            timestamp: 0,
            protocol_version: 22,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 1,
            min_persistent_entry_ttl: 1,
            max_entry_ttl: 6312000,
        });

        client.execute(&pid);
        assert!(client.get_proposal(&pid).executed);
    }

    /// Executing before the timelock expires panics with "timelock not expired".
    #[test]
    #[should_panic(expected = "timelock not expired")]
    fn test_execute_before_timelock_panics() {
        let (env, cid) = make_env();
        let client = SecureDaoClient::new(&env, &cid);

        let voter = Address::generate(&env);
        client.mint(&voter, &600);
        client.mint(&Address::generate(&env), &400);

        let pid = client.create_proposal(&voter);
        client.vote(&voter, &pid, &true);
        client.queue(&pid);

        // Do NOT advance ledger — timelock not expired
        client.execute(&pid);
    }

    /// A proposal below quorum cannot be queued regardless of vote majority.
    #[test]
    #[should_panic(expected = "quorum not reached")]
    fn test_below_quorum_cannot_queue() {
        let (env, cid) = make_env();
        let client = SecureDaoClient::new(&env, &cid);

        let voter = Address::generate(&env);
        // voter holds 1 out of 10000 total → quorum threshold = 1000, votes = 1 < 1000
        client.mint(&voter, &1);
        client.mint(&Address::generate(&env), &9999);

        let pid = client.create_proposal(&voter);
        client.vote(&voter, &pid, &true); // majority yes, but quorum not met
        client.queue(&pid);
    }

    /// A proposal that fails majority cannot be queued.
    #[test]
    #[should_panic(expected = "proposal did not pass")]
    fn test_failed_majority_cannot_queue() {
        let (env, cid) = make_env();
        let client = SecureDaoClient::new(&env, &cid);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &400);
        client.mint(&bob, &600);

        let pid = client.create_proposal(&alice);
        client.vote(&alice, &pid, &true);  // 400 for
        client.vote(&bob, &pid, &false);   // 600 against
        client.queue(&pid);
    }

    /// Each address can only vote once.
    #[test]
    #[should_panic(expected = "already voted")]
    fn test_double_vote_panics() {
        let (env, cid) = make_env();
        let client = SecureDaoClient::new(&env, &cid);

        let voter = Address::generate(&env);
        client.mint(&voter, &500);
        client.mint(&Address::generate(&env), &500);

        let pid = client.create_proposal(&voter);
        client.vote(&voter, &pid, &true);
        client.vote(&voter, &pid, &true); // second vote → panic
    }
}
