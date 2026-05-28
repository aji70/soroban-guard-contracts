use crate::Proposal;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, Symbol};

#[contracttype]
pub enum DataKey {
    NextId,
    Proposal(u64),
}

#[contract]
pub struct SecureProposalIds;

#[contractimpl]
impl SecureProposalIds {
    pub fn propose(env: Env, proposer: Address, title: Symbol, payload: Bytes) -> u64 {
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextId)
            .unwrap_or(0);
        let proposal = Proposal {
            proposer,
            title,
            payload,
            votes: 0,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage().persistent().set(&DataKey::NextId, &(id + 1));
        id
    }

    pub fn vote(env: Env, id: u64) {
        let key = DataKey::Proposal(id);
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&key)
            .expect("proposal missing");
        proposal.votes += 1;
        env.storage().persistent().set(&key, &proposal);
    }

    pub fn get(env: Env, id: u64) -> Proposal {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .expect("proposal missing")
    }
}
