#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ProposalStatus {
    Active,
    Canceled,
    Executed,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct Proposal {
    pub proposer: Address,
    pub status: ProposalStatus,
}

#[contracttype]
pub enum DataKey {
    Proposals,
    Guardian,
}

#[contract]
pub struct PublicProposalCancel;

#[contractimpl]
impl PublicProposalCancel {
    pub fn init(env: Env, guardian: Address) {
        env.storage().instance().set(&DataKey::Guardian, &guardian);
        env.storage()
            .instance()
            .set(&DataKey::Proposals, &Map::<u32, Proposal>::new(&env));
    }

    pub fn create_proposal(env: Env, proposer: Address, id: u32) {
        proposer.require_auth();
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap_or(Map::new(&env));
        proposals.set(
            id,
            Proposal {
                proposer,
                status: ProposalStatus::Active,
            },
        );
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    /// BUG: cancel marks proposals canceled without a permission check.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = (actor, amount);
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap_or(Map::new(&env));
        for (id, mut proposal) in proposals.iter() {
            if proposal.status == ProposalStatus::Active {
                proposal.status = ProposalStatus::Canceled;
                proposals.set(id, proposal);
            }
        }
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    pub fn cancel_vulnerable(env: Env, caller: Address, proposal_id: u32) {
        let _ = caller;
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap();
        let mut proposal = proposals.get(proposal_id).unwrap();
        proposal.status = ProposalStatus::Canceled;
        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    pub fn cancel_secure(env: Env, caller: Address, proposal_id: u32) {
        caller.require_auth();
        let mut proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap();
        let proposal = proposals.get(proposal_id).unwrap();
        let guardian: Address = env.storage().instance().get(&DataKey::Guardian).unwrap();
        if caller != proposal.proposer && caller != guardian {
            panic!("unauthorized: only proposer or guardian can cancel");
        }
        let mut proposal = proposal;
        proposal.status = ProposalStatus::Canceled;
        proposals.set(proposal_id, proposal);
        env.storage().instance().set(&DataKey::Proposals, &proposals);
    }

    pub fn get_status(env: Env, proposal_id: u32) -> ProposalStatus {
        let proposals: Map<u32, Proposal> = env
            .storage()
            .instance()
            .get(&DataKey::Proposals)
            .unwrap_or(Map::new(&env));
        proposals.get(proposal_id).unwrap().status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, PublicProposalCancelClient<'static>, Address, Address, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, PublicProposalCancel);
        let client = PublicProposalCancelClient::new(&env, &contract_id);
        let proposer = Address::generate(&env);
        let guardian = Address::generate(&env);
        let rogue = Address::generate(&env);
        env.mock_all_auths();
        client.init(&guardian);
        client.create_proposal(&proposer, &1u32);
        (env, client, proposer, guardian, rogue)
    }

    #[test]
    fn test_vulnerable_unauth_cancel_succeeds() {
        let (_env, client, _proposer, _guardian, rogue) = setup();
        client.cancel_vulnerable(&rogue, &1u32);
        assert_eq!(client.get_status(&1u32), ProposalStatus::Canceled);
    }

    #[test]
    fn test_boundary_proposer_can_cancel_secure() {
        let (_env, client, proposer, _guardian, _rogue) = setup();
        client.cancel_secure(&proposer, &1u32);
        assert_eq!(client.get_status(&1u32), ProposalStatus::Canceled);
    }

    #[test]
    #[should_panic(expected = "unauthorized: only proposer or guardian can cancel")]
    fn test_secure_rejects_unauthorized_cancel() {
        let (_env, client, _proposer, _guardian, rogue) = setup();
        client.cancel_secure(&rogue, &1u32);
    }
}
