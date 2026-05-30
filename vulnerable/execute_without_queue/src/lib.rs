#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map};

const TIMELOCK_DELAY: u32 = 100;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalState {
    Pending,
    Passed,
    Queued,
    Executed,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Proposal {
    pub state: ProposalState,
    pub execute_after: u32,
}

#[contracttype]
pub enum DataKey {
    Proposals,
}

#[contract]
pub struct ExecuteWithoutQueue;

#[contractimpl]
impl ExecuteWithoutQueue {
    pub fn create(env: Env, id: u32) {
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap_or(Map::new(&env));
        proposals.set(
            id,
            Proposal {
                state: ProposalState::Passed,
                execute_after: 0,
            },
        );
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    pub fn queue(env: Env, id: u32) {
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap();
        let mut proposal = proposals.get(id).unwrap();
        if proposal.state != ProposalState::Passed {
            panic!("can only queue passed proposals");
        }
        proposal.state = ProposalState::Queued;
        proposal.execute_after = env.ledger().sequence() + TIMELOCK_DELAY;
        proposals.set(id, proposal);
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    /// BUG: execution ignores queued state and execute-after ledger.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = (actor, amount);
        let proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap_or(Map::new(&env));
        for (_, proposal) in proposals.iter() {
            if proposal.state == ProposalState::Passed {
                return;
            }
        }
    }

    pub fn execute_vulnerable(env: Env, id: u32) {
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap();
        let mut proposal = proposals.get(id).unwrap();
        if proposal.state != ProposalState::Passed {
            panic!("proposal not passed");
        }
        proposal.state = ProposalState::Executed;
        proposals.set(id, proposal);
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    pub fn execute_secure(env: Env, id: u32) {
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap();
        let mut proposal = proposals.get(id).unwrap();
        if proposal.state != ProposalState::Queued {
            panic!("proposal must be queued before execution");
        }
        if env.ledger().sequence() < proposal.execute_after {
            panic!("timelock delay not elapsed");
        }
        proposal.state = ProposalState::Executed;
        proposals.set(id, proposal);
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    pub fn get_state(env: Env, id: u32) -> ProposalState {
        let proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap_or(Map::new(&env));
        proposals.get(id).unwrap().state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Ledger, Env};

    #[test]
    fn test_vulnerable_executes_without_queue_or_delay() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ExecuteWithoutQueue);
        let client = ExecuteWithoutQueueClient::new(&env, &contract_id);
        client.create(&1u32);
        client.execute_vulnerable(&1u32);
        assert_eq!(client.get_state(&1u32), ProposalState::Executed);
    }

    #[test]
    #[should_panic(expected = "proposal must be queued before execution")]
    fn test_secure_rejects_execution_without_queue() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ExecuteWithoutQueue);
        let client = ExecuteWithoutQueueClient::new(&env, &contract_id);
        client.create(&1u32);
        client.execute_secure(&1u32);
    }

    #[test]
    #[should_panic(expected = "timelock delay not elapsed")]
    fn test_secure_rejects_execution_before_delay() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ExecuteWithoutQueue);
        let client = ExecuteWithoutQueueClient::new(&env, &contract_id);
        client.create(&1u32);
        client.queue(&1u32);
        env.ledger().with_mut(|ledger| ledger.sequence_number += 50);
        client.execute_secure(&1u32);
    }

    #[test]
    fn test_secure_succeeds_after_queue_and_delay() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ExecuteWithoutQueue);
        let client = ExecuteWithoutQueueClient::new(&env, &contract_id);
        client.create(&1u32);
        client.queue(&1u32);
        env.ledger()
            .with_mut(|ledger| ledger.sequence_number += TIMELOCK_DELAY + 1);
        client.execute_secure(&1u32);
        assert_eq!(client.get_state(&1u32), ProposalState::Executed);
    }
}
