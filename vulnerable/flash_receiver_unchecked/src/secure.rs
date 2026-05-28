//! SECURE: verify receiver callback success and full principal + fee repayment.

use super::{callback, DataKey, RepaymentLedgerClient, FLASH_FEE};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureFlashReceiver;

#[contractimpl]
impl SecureFlashReceiver {
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

    /// SECURE: require callback success and repayment of amount + fee.
    pub fn flash_loan(env: Env, receiver: Address, amount: i128, ledger: Address) {
        let pool: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        assert!(pool >= amount, "insufficient liquidity");

        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(pool - amount));

        let ok = callback::ReceiverClient::new(&env, &receiver).on_flash_loan(
            &env.current_contract_address(),
            &amount,
            &FLASH_FEE,
        );
        assert!(ok, "receiver callback failed");

        let repaid = RepaymentLedgerClient::new(&env, &ledger).consume_repayment();
        assert!(repaid >= amount + FLASH_FEE, "flash loan underpaid");

        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::PoolBalance, &(current + repaid));
    }

    pub fn pool_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::PoolBalance)
            .unwrap_or(0)
    }
}
