//! VULNERABLE: Proposal ID Collision Overwrites Active Proposals
//!
//! Proposal identity is derived only from proposer and title. A second proposal
//! with the same pair overwrites the first proposal and its votes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env, Symbol};

pub mod secure;

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct Proposal {
    pub proposer: Address,
    pub title: Symbol,
    pub payload: Bytes,
    pub votes: u32,
}

#[contracttype]
pub enum DataKey {
    Proposal(Address, Symbol),
}

#[contract]
pub struct ProposalIdCollision;

#[contractimpl]
impl ProposalIdCollision {
    pub fn propose(env: Env, proposer: Address, title: Symbol, payload: Bytes) {
        let proposal = Proposal {
            proposer: proposer.clone(),
            title: title.clone(),
            payload,
            votes: 0,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposer, title), &proposal);
    }

    pub fn vote(env: Env, proposer: Address, title: Symbol) {
        let key = DataKey::Proposal(proposer, title);
        let mut proposal: Proposal = env
            .storage()
            .persistent()
            .get(&key)
            .expect("proposal missing");
        proposal.votes += 1;
        env.storage().persistent().set(&key, &proposal);
    }

    pub fn get(env: Env, proposer: Address, title: Symbol) -> Proposal {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(proposer, title))
            .expect("proposal missing")
    }

    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let mut payload = Bytes::new(&env);
        payload.push_back(amount as u8);
        Self::propose(env, actor, Symbol::new(&env, "audit"), payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env, Symbol};

    fn bytes(env: &Env, value: u8) -> Bytes {
        let mut bytes = Bytes::new(env);
        bytes.push_back(value);
        bytes
    }

    #[test]
    fn vulnerable_path() {
        let env = Env::default();
        let id = env.register_contract(None, ProposalIdCollision);
        let client = ProposalIdCollisionClient::new(&env, &id);
        let proposer = Address::generate(&env);
        let title = Symbol::new(&env, "upgrade");

        client.propose(&proposer, &title, &bytes(&env, 1));
        client.propose(&proposer, &title, &bytes(&env, 2));

        let stored = client.get(&proposer, &title);
        assert_eq!(stored.payload, bytes(&env, 2));
        assert_eq!(stored.votes, 0);
    }

    #[test]
    fn boundary() {
        let env = Env::default();
        let id = env.register_contract(None, ProposalIdCollision);
        let client = ProposalIdCollisionClient::new(&env, &id);
        let proposer = Address::generate(&env);
        let title = Symbol::new(&env, "upgrade");

        client.propose(&proposer, &title, &bytes(&env, 1));
        client.vote(&proposer, &title);
        assert_eq!(client.get(&proposer, &title).votes, 1);

        client.propose(&proposer, &title, &bytes(&env, 2));
        assert_eq!(client.get(&proposer, &title).votes, 0);
    }

    #[test]
    fn secure_path() {
        use crate::secure::SecureProposalIdsClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureProposalIds);
        let client = SecureProposalIdsClient::new(&env, &id);
        let proposer = Address::generate(&env);
        let title = Symbol::new(&env, "upgrade");

        let first = client.propose(&proposer, &title, &bytes(&env, 1));
        client.vote(&first);
        let second = client.propose(&proposer, &title, &bytes(&env, 2));

        assert_ne!(first, second);
        assert_eq!(client.get(&first).votes, 1);
        assert_eq!(client.get(&second).votes, 0);
    }
}
