//! SECURE: Bind signed reports to the target contract and scanner identity.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};
use super::DataKey;

pub fn secure_report_signature(
    env: &Env,
    target_contract: &Address,
    scanner: &Address,
    report_hash: &BytesN<32>,
    nonce: u64,
) -> BytesN<32> {
    let mut msg = Bytes::new(env);
    msg.append(&target_contract.to_xdr(env));
    msg.append(&scanner.to_xdr(env));
    msg.append(&report_hash.to_xdr(env));
    msg.append(&Bytes::from_array(env, &nonce.to_be_bytes()));
    env.crypto().sha256(&msg).into()
}

#[contract]
pub struct SecureReportHashUnboundContract;

#[contractimpl]
impl SecureReportHashUnboundContract {
    pub fn submit_report(
        env: Env,
        scanner: Address,
        target_contract: Address,
        report_hash: BytesN<32>,
        nonce: u64,
        signature: BytesN<32>,
    ) {
        scanner.require_auth();
        let expected = secure_report_signature(&env, &target_contract, &scanner, &report_hash, nonce);
        assert_eq!(signature, expected, "invalid report signature");
        env.storage()
            .persistent()
            .set(&DataKey::Report(target_contract), &report_hash);
    }

    pub fn get_report(env: Env, target_contract: Address) -> Option<BytesN<32>> {
        env.storage().persistent().get(&DataKey::Report(target_contract))
    }

    pub fn report_signature(
        env: Env,
        scanner: Address,
        target_contract: Address,
        report_hash: BytesN<32>,
        nonce: u64,
    ) -> BytesN<32> {
        secure_report_signature(&env, &target_contract, &scanner, &report_hash, nonce)
    }
}
