use crate::Proposal;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Env, Symbol, Val, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum ContractError {
    TargetNotAllowed = 1,
    FunctionNotAllowed = 2,
}

#[contracttype]
pub enum DataKey {
    NextId,
    Proposal(u64),
    AllowedTargets,
    AllowedFunctions,
}

#[contract]
pub struct SecureGovernance;

#[contractimpl]
impl SecureGovernance {
    pub fn allow_target(env: Env, target: Address) {
        let mut targets: Vec<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::AllowedTargets)
            .unwrap_or(Vec::new(&env));
        targets.push_back(target);
        env.storage()
            .persistent()
            .set(&DataKey::AllowedTargets, &targets);
    }

    pub fn allow_function(env: Env, function: Symbol) {
        let mut functions: Vec<Symbol> = env
            .storage()
            .persistent()
            .get(&DataKey::AllowedFunctions)
            .unwrap_or(Vec::new(&env));
        functions.push_back(function);
        env.storage()
            .persistent()
            .set(&DataKey::AllowedFunctions, &functions);
    }

    pub fn propose(env: Env, proposal: Proposal) -> Result<u64, ContractError> {
        ensure_allowed(&env, &proposal)?;
        let id: u64 = env
            .storage()
            .persistent()
            .get(&DataKey::NextId)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage().persistent().set(&DataKey::NextId, &(id + 1));
        Ok(id)
    }

    pub fn execute(env: Env, proposal_id: u64) -> Result<Val, ContractError> {
        let proposal: Proposal = env
            .storage()
            .persistent()
            .get(&DataKey::Proposal(proposal_id))
            .expect("proposal missing");
        ensure_allowed(&env, &proposal)?;
        Ok(env.invoke_contract(&proposal.target, &proposal.function, proposal.args))
    }
}

fn ensure_allowed(env: &Env, proposal: &Proposal) -> Result<(), ContractError> {
    let targets: Vec<Address> = env
        .storage()
        .persistent()
        .get(&DataKey::AllowedTargets)
        .unwrap_or(Vec::new(env));
    if !targets.contains(&proposal.target) {
        return Err(ContractError::TargetNotAllowed);
    }

    let functions: Vec<Symbol> = env
        .storage()
        .persistent()
        .get(&DataKey::AllowedFunctions)
        .unwrap_or(Vec::new(env));
    if !functions.contains(&proposal.function) {
        return Err(ContractError::FunctionNotAllowed);
    }
    Ok(())
}
