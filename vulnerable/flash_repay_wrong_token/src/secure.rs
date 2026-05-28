//! SECURE: Flash loan repayment bound to the borrowed asset.

use super::{callback, DataKey};
use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct SecureFlashRepay;

#[contractimpl]
impl SecureFlashRepay {
    pub fn deposit(env: Env, token_addr: Address, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&env, &token_addr).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
    }

    pub fn flash_loan(env: Env, borrower: Address, asset: Address, amount: i128) {
        let fee = amount / 100;
        let required = amount + fee;

        let asset_client = token::Client::new(&env, &asset);
        let balance_before = asset_client.balance(&env.current_contract_address());
        assert!(balance_before >= amount, "insufficient liquidity");

        asset_client.transfer(
            &env.current_contract_address(),
            &borrower,
            &amount,
        );

        callback::BorrowerClient::new(&env, &borrower).on_flash_loan(
            &env.current_contract_address(),
            &asset,
            &amount,
            &required,
        );

        let balance_after = asset_client.balance(&env.current_contract_address());
        assert!(
            balance_after >= balance_before + fee,
            "flash loan not repaid in borrowed asset"
        );
        env.storage().persistent().set(&DataKey::LoanRepaid, &true);
    }

    pub fn is_repaid(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::LoanRepaid)
            .unwrap_or(false)
    }
}
