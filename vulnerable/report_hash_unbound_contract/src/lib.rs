//! VULNERABLE: Report hash signature omits the contract address.
//!
//! A registry-like report submission contract that verifies a signed report hash
//! but does not bind the signed payload to the target contract address. A valid
//! report for one contract can be replayed against another.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Report(Address),
}

pub fn vulnerable_report_signature(env: &Env, report_hash: &BytesN<32>) -> BytesN<32> {
    let mut msg = Bytes::new(env);
    msg.append(&report_hash.to_xdr(env));
    env.crypto().sha256(&msg).into()
}

#[contract]
pub struct ReportHashUnboundContract;

#[contractimpl]
impl ReportHashUnboundContract {
    pub fn submit_report(
        env: Env,
        scanner: Address,
        target_contract: Address,
        report_hash: BytesN<32>,
        signature: BytesN<32>,
    ) {
        scanner.require_auth();
        let expected = vulnerable_report_signature(&env, &report_hash);
        assert_eq!(signature, expected, "invalid report signature");
        env.storage()
            .persistent()
            .set(&DataKey::Report(target_contract), &report_hash);
    }

    pub fn get_report(env: Env, target_contract: Address) -> Option<BytesN<32>> {
        env.storage().persistent().get(&DataKey::Report(target_contract))
    }

    pub fn report_signature(env: Env, report_hash: BytesN<32>) -> BytesN<32> {
        vulnerable_report_signature(&env, &report_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

    #[test]
    fn test_vulnerable_report_replay_across_target_contracts() {
        let env = Env::default();
        let contract_id = env.register_contract(None, ReportHashUnboundContract);
        let client = ReportHashUnboundContractClient::new(&env, &contract_id);

        let scanner = Address::generate(&env);
        let target_contract_a = Address::generate(&env);
        let target_contract_b = Address::generate(&env);
        let report_hash = BytesN::from_array(&env, &[1u8; 32]);

        env.mock_all_auths();
        let signature = client.report_signature(&report_hash);

        client.submit_report(&scanner, &target_contract_a, &report_hash, &signature);
        client.submit_report(&scanner, &target_contract_b, &report_hash, &signature);

        assert_eq!(client.get_report(&target_contract_a), Some(report_hash));
        assert_eq!(client.get_report(&target_contract_b), Some(report_hash));
    }

    #[test]
    fn test_secure_report_replay_fails_between_targets() {
        let env = Env::default();
        let secure_id = env.register_contract(None, secure::SecureReportHashUnboundContract);
        let client = secure::SecureReportHashUnboundContractClient::new(&env, &secure_id);

        let scanner = Address::generate(&env);
        let target_contract_a = Address::generate(&env);
        let target_contract_b = Address::generate(&env);
        let report_hash = BytesN::from_array(&env, &[1u8; 32]);
        let nonce = 1u64;

        env.mock_all_auths();
        let signature_a = client.report_signature(&scanner, &target_contract_a, &report_hash, &nonce);

        client.submit_report(&scanner, &target_contract_a, &report_hash, &nonce, &signature_a);

        let result = std::panic::catch_unwind(|| {
            client.submit_report(&scanner, &target_contract_b, &report_hash, &nonce, &signature_a);
        });
        assert!(result.is_err());
    }
}
