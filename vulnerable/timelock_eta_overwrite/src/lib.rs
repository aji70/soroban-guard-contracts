//! VULNERABLE: Timelock ETA Can Be Overwritten After Queue
//!
//! A queued proposal's `execute_after` ledger can be changed after voting. An
//! attacker can shorten the delay and execute before the original timelock.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Env};

pub mod secure;

#[contracttype]
#[derive(Clone)]
pub struct QueuedProposal {
    pub execute_after: u32,
    pub executed: bool,
}

#[contracttype]
pub enum DataKey {
    Proposal(u32),
}

fn proposal(env: &Env, id: u32) -> QueuedProposal {
    env.storage()
        .persistent()
        .get(&DataKey::Proposal(id))
        .expect("missing proposal")
}

fn save_proposal(env: &Env, id: u32, proposal: &QueuedProposal) {
    env.storage()
        .persistent()
        .set(&DataKey::Proposal(id), proposal);
}

#[contract]
pub struct TimelockEtaOverwrite;

#[contractimpl]
impl TimelockEtaOverwrite {
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

    pub fn set_execute_after(env: Env, id: u32, execute_after: u32) {
        let mut proposal = proposal(&env, id);
        // VULNERABLE: queued ETA can be overwritten without cancel and requeue.
        proposal.execute_after = execute_after;
        save_proposal(&env, id, &proposal);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::{SecureTimelockEta, SecureTimelockEtaClient};
    use soroban_sdk::{
        testutils::{Ledger, LedgerInfo},
        Env,
    };

    fn env_at(sequence: u32) -> Env {
        let env = Env::default();
        env.ledger().set(LedgerInfo {
            timestamp: 1,
            protocol_version: 22,
            sequence_number: sequence,
            network_id: Default::default(),
            base_reserve: 10,
            min_temp_entry_ttl: 16,
            min_persistent_entry_ttl: 16,
            max_entry_ttl: 100_000,
        });
        env
    }

    #[test]
    fn vulnerable_eta_overwrite_executes_early() {
        let env = env_at(100);
        let id = env.register_contract(None, TimelockEtaOverwrite);
        let client = TimelockEtaOverwriteClient::new(&env, &id);

        client.queue(&1, &200);
        client.set_execute_after(&1, &100);
        client.execute(&1);

        assert_eq!(client.state(&1), (100, true));
    }

    #[test]
    #[should_panic(expected = "eta immutable")]
    fn secure_rejects_eta_mutation() {
        let env = env_at(100);
        let id = env.register_contract(None, SecureTimelockEta);
        let client = SecureTimelockEtaClient::new(&env, &id);

        client.queue(&1, &200);
        client.set_execute_after(&1, &100);
    }
}
