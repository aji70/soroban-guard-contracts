//! VULNERABLE: Governance Call Target Is Not Allowlisted
//!
//! Passed proposals can execute arbitrary target/function pairs. The DAO never
//! checks that a target or function is approved.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol, Val, Vec,
};

pub mod secure;

#[derive(Clone)]
#[contracttype]
pub struct Proposal {
    pub target: Address,
    pub function: Symbol,
    pub args: Vec<Val>,
}

#[contracttype]
pub enum DataKey {
    NextId,
    Proposal(u64),
    Executed(u64),
}

#[contract]
pub struct GovernanceTargetUnvalidated;

#[contractimpl]
impl GovernanceTargetUnvalidated {
    pub fn propose(env: Env, proposal: Proposal) -> u64 {
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextId)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage().persistent().set(&DataKey::NextId, &(id + 1));
        id
    }

    pub fn execute(env: Env, proposal_id: u64) -> Val {
        let proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal missing");
        let result: Val = env.invoke_contract(&proposal.target, &proposal.function, proposal.args);
        env.storage()
            .persistent()
            .set(&DataKey::Executed(proposal_id), &true);
        result
    }

    pub fn executed(env: Env, proposal_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Executed(proposal_id))
            .unwrap_or(false)
    }

    pub fn dao_ping(_env: Env) -> u32 {
        7
    }

    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let proposal = Proposal {
            target: actor,
            function: symbol_short!("ping"),
            args: Vec::new(&env),
        };
        let _ = Self::propose(env, proposal);
        let _ = amount;
    }
}

#[contract]
pub struct UnintendedTarget;

#[contractimpl]
impl UnintendedTarget {
    pub fn ping(_env: Env) -> u32 {
        42
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, IntoVal};

    #[test]
    fn vulnerable_path() {
        let env = Env::default();
        let dao_id = env.register_contract(None, GovernanceTargetUnvalidated);
        let target_id = env.register_contract(None, UnintendedTarget);
        let dao = GovernanceTargetUnvalidatedClient::new(&env, &dao_id);

        let proposal = Proposal {
            target: target_id,
            function: symbol_short!("ping"),
            args: Vec::new(&env),
        };
        let id = dao.propose(&proposal);
        assert_eq!(dao.execute(&id), 42u32.into_val(&env));
        assert!(dao.executed(&id));
    }

    #[test]
    fn boundary() {
        let env = Env::default();
        let dao_id = env.register_contract(None, GovernanceTargetUnvalidated);
        let dao = GovernanceTargetUnvalidatedClient::new(&env, &dao_id);

        let proposal = Proposal {
            target: dao_id.clone(),
            function: symbol_short!("dao_ping"),
            args: Vec::new(&env),
        };
        let id = dao.propose(&proposal);
        assert_eq!(dao.execute(&id), 7u32.into_val(&env));
    }

    #[test]
    fn secure_path() {
        use crate::secure::SecureGovernanceClient;

        let env = Env::default();
        let gov_id = env.register_contract(None, secure::SecureGovernance);
        let target_id = env.register_contract(None, UnintendedTarget);
        let gov = SecureGovernanceClient::new(&env, &gov_id);

        let proposal = Proposal {
            target: target_id,
            function: symbol_short!("ping"),
            args: Vec::new(&env),
        };
        assert!(gov.try_propose(&proposal).is_err());
    }
}
