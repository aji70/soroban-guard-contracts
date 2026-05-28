use soroban_sdk::{contract, contractimpl, token, Address, Env};

use super::DataKey;

#[contract]
pub struct SecureAirdrop;

#[contractimpl]
impl SecureAirdrop {
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

    pub fn claim(env: Env, claimant: Address, amount: i128) {
        claimant.require_auth();

        let start_ledger: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::StartLedger)
            .expect("not initialized");
        assert!(
            env.ledger().sequence() >= start_ledger,
            "campaign has not started"
        );

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
