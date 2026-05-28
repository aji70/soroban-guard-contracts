//! VULNERABLE: Claim Can Execute Before Airdrop Start Ledger
//!
//! The campaign stores a `start_ledger` at initialization, but the claim
//! function never reads or checks it, allowing claims before launch.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Token,
    StartLedger,
    Claimed(Address),
}

#[contract]
pub struct VulnerableAirdrop;

#[contractimpl]
impl VulnerableAirdrop {
    pub fn initialize(env: Env, admin: Address, token_addr: Address, start_ledger: u32) {
        assert!(
            !env.storage().persistent().has(&DataKey::Admin),
            "already initialized"
        );
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Token, &token_addr);
        env.storage()
            .persistent()
            .set(&DataKey::StartLedger, &start_ledger);
    }

    pub fn fund(env: Env, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let token_addr: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token_addr).transfer(
            &admin,
            &env.current_contract_address(),
            &amount,
        );
    }

    /// ❌ Never reads `start_ledger` — claims succeed at any ledger.
    pub fn claim(env: Env, claimant: Address, amount: i128) {
        claimant.require_auth();

        let claimed_key = DataKey::Claimed(claimant.clone());
        assert!(
            !env.storage().persistent().has(&claimed_key),
            "already claimed"
        );
        env.storage().persistent().set(&claimed_key, &true);

        let token_addr: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        token::Client::new(&env, &token_addr).transfer(
            &env.current_contract_address(),
            &claimant,
            &amount,
        );
    }

    pub fn is_claimed(env: Env, claimant: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Claimed(claimant))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::SecureAirdropClient;
    use soroban_sdk::{
        testutils::{Address as _, Ledger},
        token::{Client as TokenClient, StellarAssetClient},
        Address, Env,
    };

    const START_LEDGER: u32 = 500;
    const CLAIM_AMOUNT: i128 = 250;

    fn setup(env: &Env) -> (Address, Address, Address) {
        let admin = Address::generate(env);
        let claimant = Address::generate(env);
        let token_admin = Address::generate(env);
        let token = env
            .register_stellar_asset_contract_v2(token_admin.clone())
            .address();
        StellarAssetClient::new(env, &token).mint(&admin, &10_000);
        (token, admin, claimant)
    }

    #[test]
    fn test_vulnerable_claim_before_start_pays_out() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(100);

        let (token, admin, claimant) = setup(&env);
        let contract_id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token, &START_LEDGER);
        client.fund(&CLAIM_AMOUNT);

        client.claim(&claimant, &CLAIM_AMOUNT);

        assert!(client.is_claimed(&claimant));
        assert_eq!(TokenClient::new(&env, &token).balance(&claimant), CLAIM_AMOUNT);
    }

    #[test]
    fn test_vulnerable_boundary_claim_at_start_minus_one() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(START_LEDGER - 1);

        let (token, admin, claimant) = setup(&env);
        let contract_id = env.register_contract(None, VulnerableAirdrop);
        let client = VulnerableAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token, &START_LEDGER);
        client.fund(&CLAIM_AMOUNT);

        client.claim(&claimant, &CLAIM_AMOUNT);
        assert_eq!(TokenClient::new(&env, &token).balance(&claimant), CLAIM_AMOUNT);
    }

    #[test]
    #[should_panic(expected = "campaign has not started")]
    fn test_secure_rejects_early_claim() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(START_LEDGER - 1);

        let (token, admin, claimant) = setup(&env);
        let contract_id = env.register_contract(None, secure::SecureAirdrop);
        let client = SecureAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token, &START_LEDGER);
        client.fund(&CLAIM_AMOUNT);

        client.claim(&claimant, &CLAIM_AMOUNT);
    }

    #[test]
    fn test_secure_accepts_claim_at_start_ledger() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(START_LEDGER);

        let (token, admin, claimant) = setup(&env);
        let contract_id = env.register_contract(None, secure::SecureAirdrop);
        let client = SecureAirdropClient::new(&env, &contract_id);

        client.initialize(&admin, &token, &START_LEDGER);
        client.fund(&CLAIM_AMOUNT);

        client.claim(&claimant, &CLAIM_AMOUNT);
        assert_eq!(TokenClient::new(&env, &token).balance(&claimant), CLAIM_AMOUNT);
    }
}
