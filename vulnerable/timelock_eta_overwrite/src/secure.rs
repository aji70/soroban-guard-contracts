//! SECURE: Queued ETA is immutable; callers must cancel and requeue.

use super::{proposal, save_proposal, QueuedProposal};
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct SecureTimelockEta;

#[contractimpl]
impl SecureTimelockEta {
    pub fn queue(env: Env, id: u32, execute_after: u32) {
        save_proposal(
            &env,
            id,
            &QueuedProposal {
                execute_after,
                executed: false,
            },
        );
    }

    pub fn set_execute_after(_env: Env, _id: u32, _execute_after: u32) {
        panic!("eta immutable");
    }

    pub fn execute(env: Env, id: u32) {
        let mut proposal = proposal(&env, id);
        assert!(!proposal.executed, "already executed");
        assert!(
            env.ledger().sequence() >= proposal.execute_after,
            "timelock active"
        );
        proposal.executed = true;
        save_proposal(&env, id, &proposal);
    }

    pub fn state(env: Env, id: u32) -> (u32, bool) {
        let proposal = proposal(&env, id);
        (proposal.execute_after, proposal.executed)
    }
}
