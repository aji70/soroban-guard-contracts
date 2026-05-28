//! VULNERABLE: Scan Result Overwrite Erases Prior Critical Finding
//!
//! Stores exactly one scan result per contract. Any later submission replaces
//! the prior finding, so an informational result can erase a critical one.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String};

pub mod secure;

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub enum Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ScanResult {
    pub severity: Severity,
    pub detail: String,
}

#[contracttype]
pub enum DataKey {
    Result(Address),
}

#[contract]
pub struct ScanResultOverwrite;

#[contractimpl]
impl ScanResultOverwrite {
    pub fn submit(env: Env, contract: Address, severity: Severity, detail: String) {
        let result = ScanResult { severity, detail };
        env.storage()
            .persistent()
            .set(&DataKey::Result(contract), &result);
    }

    pub fn latest(env: Env, contract: Address) -> Option<ScanResult> {
        env.storage().persistent().get(&DataKey::Result(contract))
    }

    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let detail = String::from_str(&env, "scanner hook");
        let severity = if amount > 0 {
            Severity::Informational
        } else {
            Severity::Critical
        };
        Self::submit(env, actor, severity, detail);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, String};

    fn setup() -> (Env, ScanResultOverwriteClient<'static>, Address) {
        let env = Env::default();
        let id = env.register_contract(None, ScanResultOverwrite);
        let client = ScanResultOverwriteClient::new(&env, &id);
        let target = Address::generate(&env);
        (env, client, target)
    }

    #[test]
    fn vulnerable_path() {
        let (env, client, target) = setup();
        client.submit(
            &target,
            &Severity::Critical,
            &String::from_str(&env, "critical"),
        );
        client.submit(
            &target,
            &Severity::Informational,
            &String::from_str(&env, "info"),
        );

        let stored = client.latest(&target).unwrap();
        assert_eq!(stored.severity, Severity::Informational);
        assert_eq!(stored.detail, String::from_str(&env, "info"));
    }

    #[test]
    fn boundary() {
        let (env, client, target) = setup();
        client.submit(
            &target,
            &Severity::Critical,
            &String::from_str(&env, "first"),
        );
        client.submit(
            &target,
            &Severity::Critical,
            &String::from_str(&env, "second"),
        );

        let stored = client.latest(&target).unwrap();
        assert_eq!(stored.severity, Severity::Critical);
        assert_eq!(stored.detail, String::from_str(&env, "second"));
    }

    #[test]
    fn secure_path() {
        use crate::secure::SecureScanResultsClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureScanResults);
        let client = SecureScanResultsClient::new(&env, &id);
        let target = Address::generate(&env);

        client.submit(
            &target,
            &Severity::Critical,
            &String::from_str(&env, "critical"),
        );
        client.submit(
            &target,
            &Severity::Informational,
            &String::from_str(&env, "info"),
        );

        assert_eq!(
            client.latest(&target).unwrap().severity,
            Severity::Informational
        );
        assert_eq!(
            client.highest(&target).unwrap().severity,
            Severity::Critical
        );
        assert_eq!(client.history(&target).len(), 2);
    }
}
