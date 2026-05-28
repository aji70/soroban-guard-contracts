use crate::{ScanResult, Severity};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};

const HISTORY_CAP: u32 = 50;

#[contracttype]
pub enum DataKey {
    Latest(Address),
    Highest(Address),
    History(Address),
}

#[contract]
pub struct SecureScanResults;

#[contractimpl]
impl SecureScanResults {
    pub fn submit(env: Env, contract: Address, severity: Severity, detail: String) {
        let result = ScanResult { severity, detail };
        env.storage()
            .persistent()
            .set(&DataKey::Latest(contract.clone()), &result);

        let highest = env
            .storage()
            .persistent()
            .get::<_, ScanResult>(&DataKey::Highest(contract.clone()));
        if highest
            .as_ref()
            .map(|prior| rank(&result.severity) >= rank(&prior.severity))
            .unwrap_or(true)
        {
            env.storage()
                .persistent()
                .set(&DataKey::Highest(contract.clone()), &result);
        }

        let mut history: Vec<ScanResult> = env
            .storage()
            .persistent()
            .get(&DataKey::History(contract.clone()))
            .unwrap_or(Vec::new(&env));
        if history.len() >= HISTORY_CAP {
            history.pop_front();
        }
        history.push_back(result);
        env.storage()
            .persistent()
            .set(&DataKey::History(contract), &history);
    }

    pub fn latest(env: Env, contract: Address) -> Option<ScanResult> {
        env.storage().persistent().get(&DataKey::Latest(contract))
    }

    pub fn highest(env: Env, contract: Address) -> Option<ScanResult> {
        env.storage().persistent().get(&DataKey::Highest(contract))
    }

    pub fn history(env: Env, contract: Address) -> Vec<ScanResult> {
        env.storage()
            .persistent()
            .get(&DataKey::History(contract))
            .unwrap_or(Vec::new(&env))
    }
}

fn rank(severity: &Severity) -> u32 {
    match severity {
        Severity::Informational => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}
