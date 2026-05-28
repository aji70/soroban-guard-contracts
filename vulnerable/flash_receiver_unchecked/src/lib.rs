//! VULNERABLE: Flash Loan Receiver Contract Is Not Authenticated
//!
//! The lender invokes any receiver callback without verifying its return value
//! or enforcing repayment of principal plus fee.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const FLASH_FEE: i128 = 10;

#[contracttype]
pub enum DataKey {
    PoolBalance,
    LedgerContract,
}

#[contracttype]
pub enum LedgerKey {
    Repaid,
}

#[contract]
pub struct RepaymentLedger;

#[contractimpl]
impl RepaymentLedger {
    pub fn record_repayment(env: Env, amount: i128) {
        let current: i128 = env
            .storage()
            .temporary()
            .get(&LedgerKey::Repaid)
            .unwrap_or(0);
        env.storage()
            .temporary()
            .set(&LedgerKey::Repaid, &(current + amount));
    }

    pub fn consume_repayment(env: Env) -> i128 {
        let amount: i128 = env
            .storage()
            .temporary()
            .get(&LedgerKey::Repaid)
            .unwrap_or(0);
        env.storage().temporary().remove(&LedgerKey::Repaid);
        amount
    }
}

pub mod callback {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "ReceiverClient")]
    pub trait FlashReceiver {
        fn on_flash_loan(env: Env, lender: Address, amount: i128, fee: i128) -> bool;
    }
}

#[contract]
pub struct FlashReceiverUnchecked;

#[contractimpl]
impl FlashReceiverUnchecked {
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(pool + amount));
    }

    /// VULNERABLE: no return-value check and no repayment enforcement.
    pub fn flash_loan(env: Env, receiver: Address, amount: i128) {
        let pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        assert!(pool >= amount, "insufficient liquidity");

        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(pool - amount));

        // ❌ Ignores return value and never verifies principal + fee repayment.
        callback::ReceiverClient::new(&env, &receiver).on_flash_loan(
            &env.current_contract_address(),
            &amount,
            &FLASH_FEE,
        );
    }

    pub fn pool_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0)
    }
}

/// Ignores the callback and never records repayment.
pub mod ignoring {
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct IgnoringReceiver;

    #[contractimpl]
    impl IgnoringReceiver {
        pub fn on_flash_loan(_env: Env, _lender: Address, _amount: i128, _fee: i128) -> bool {
            false
        }
    }
}

/// Repays principal only, omitting the flash fee.
pub mod principal_only {
    use super::{DataKey, RepaymentLedgerClient};
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct PrincipalOnlyReceiver;

    #[contractimpl]
    impl PrincipalOnlyReceiver {
        pub fn on_flash_loan(env: Env, _lender: Address, amount: i128, _fee: i128) -> bool {
            let ledger: Address = env
                .storage()
                .persistent()
                .get(&DataKey::LedgerContract)
                .expect("ledger not configured");
            RepaymentLedgerClient::new(&env, &ledger).record_repayment(&amount);
            true
        }
    }
}

/// Repays principal plus fee and signals success.
pub mod full_repay {
    use super::{DataKey, RepaymentLedgerClient};
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct FullRepayReceiver;

    #[contractimpl]
    impl FullRepayReceiver {
        pub fn on_flash_loan(env: Env, _lender: Address, amount: i128, fee: i128) -> bool {
            let ledger: Address = env
                .storage()
                .persistent()
                .get(&DataKey::LedgerContract)
                .expect("ledger not configured");
            RepaymentLedgerClient::new(&env, &ledger).record_repayment(&(amount + fee));
            true
        }
    }
}

/// Returns failure without repaying.
pub mod failing {
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct FailingReceiver;

    #[contractimpl]
    impl FailingReceiver {
        pub fn on_flash_loan(_env: Env, _lender: Address, _amount: i128, _fee: i128) -> bool {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureFlashReceiverClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    const LOAN_AMOUNT: i128 = 500;
    const POOL_SEED: i128 = 1_000;

    fn setup_vulnerable(env: &Env) -> FlashReceiverUncheckedClient<'_> {
        let id = env.register_contract(None, FlashReceiverUnchecked);
        let client = FlashReceiverUncheckedClient::new(env, &id);
        let seeder = Address::generate(env);
        client.deposit(&seeder, &POOL_SEED);
        client
    }

    fn setup_secure(env: &Env) -> (Address, SecureFlashReceiverClient<'_>) {
        let ledger = env.register_contract(None, RepaymentLedger);
        let id = env.register_contract(None, secure::SecureFlashReceiver);
        let client = SecureFlashReceiverClient::new(env, &id);
        let seeder = Address::generate(env);
        client.deposit(&seeder, &POOL_SEED);
        (ledger, client)
    }

    fn configure_ledger(env: &Env, receiver: &Address, ledger: &Address) {
        env.as_contract(receiver, || {
            env.storage()
                .persistent()
                .set(&DataKey::LedgerContract, ledger);
        });
    }

    #[test]
    fn test_vulnerable_ignoring_receiver_drains_pool() {
        let env = Env::default();
        env.mock_all_auths();

        let client = setup_vulnerable(&env);
        let receiver = env.register_contract(None, ignoring::IgnoringReceiver);

        client.flash_loan(&receiver, &LOAN_AMOUNT);

        assert_eq!(client.pool_balance(), POOL_SEED - LOAN_AMOUNT);
    }

    #[test]
    fn test_vulnerable_principal_only_without_fee_accepted() {
        let env = Env::default();
        env.mock_all_auths();

        let ledger = env.register_contract(None, RepaymentLedger);
        let client = setup_vulnerable(&env);
        let receiver = env.register_contract(None, principal_only::PrincipalOnlyReceiver);
        configure_ledger(&env, &receiver, &ledger);

        client.flash_loan(&receiver, &LOAN_AMOUNT);

        let repaid = RepaymentLedgerClient::new(&env, &ledger).consume_repayment();
        assert_eq!(repaid, LOAN_AMOUNT);
        assert_eq!(client.pool_balance(), POOL_SEED - LOAN_AMOUNT);
    }

    #[test]
    #[should_panic(expected = "receiver callback failed")]
    fn test_secure_rejects_failing_receiver() {
        let env = Env::default();
        env.mock_all_auths();

        let (ledger, client) = setup_secure(&env);
        let receiver = env.register_contract(None, failing::FailingReceiver);

        client.flash_loan(&receiver, &LOAN_AMOUNT, &ledger);
    }

    #[test]
    #[should_panic(expected = "flash loan underpaid")]
    fn test_secure_rejects_principal_only_repayment() {
        let env = Env::default();
        env.mock_all_auths();

        let (ledger, client) = setup_secure(&env);
        let receiver = env.register_contract(None, principal_only::PrincipalOnlyReceiver);
        configure_ledger(&env, &receiver, &ledger);

        client.flash_loan(&receiver, &LOAN_AMOUNT, &ledger);
    }
}
