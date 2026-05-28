//! VULNERABLE: External Callback Can Mutate State Before Invariant Check
//!
//! A pool contract issues an external callback (e.g. a flash-loan notification)
//! before verifying that its reserve balance is still whole. The callback can
//! deposit additional funds into the pool, causing the post-callback balance
//! check to pass even though the original withdrawal was never repaid.
//!
//! VULNERABILITY: the invariant check (`balance >= reserve`) runs *after* the
//! external callback, which is free to inflate the balance and satisfy the check.
//!
//! SECURE MIRROR: `secure::SecurePool` snapshots the required reserve *before*
//! the callback and validates against that immutable snapshot afterwards,
//! so callback-driven inflation cannot forge a passing check.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    /// Pool reserve: the minimum balance that must be present after a flash loan.
    Reserve,
    /// Pool balance: tracks deposits and repayments.
    Balance,
    /// Simulated flag: when true the mock callback inflates the balance.
    CallbackInflates,
}

#[contract]
pub struct VulnerablePool;

#[contractimpl]
impl VulnerablePool {
    pub fn initialize(env: Env, reserve: i128) {
        if env.storage().persistent().has(&DataKey::Reserve) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Reserve, &reserve);
        env.storage().persistent().set(&DataKey::Balance, &reserve);
        env.storage()
            .persistent()
            .set(&DataKey::CallbackInflates, &false);
    }

    /// Toggle the simulated callback-inflation flag.
    pub fn set_callback_inflates(env: Env, inflates: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::CallbackInflates, &inflates);
    }

    /// Simulated external callback. When `callback_inflates` is true it
    /// deposits extra funds into the pool, mimicking a reentrancy-style
    /// balance manipulation.
    fn run_callback(env: &Env) {
        let inflates: bool = env
            .storage()
            .persistent()
            .get(&DataKey::CallbackInflates)
            .unwrap_or(false);
        if inflates {
            // Callback inflates the balance to satisfy the upcoming check.
            let bal: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::Balance)
                .unwrap_or(0);
            let reserve: i128 = env
                .storage()
                .persistent()
                .get(&DataKey::Reserve)
                .unwrap_or(0);
            // Deposit just enough to meet the reserve.
            if bal < reserve {
                env.storage().persistent().set(&DataKey::Balance, &reserve);
            }
        }
    }

    /// VULNERABLE: issues the callback before checking the invariant.
    ///
    /// # Vulnerability
    /// `run_callback` executes before `balance >= reserve` is verified.
    /// The callback can inflate the balance, making the check pass even
    /// when the pool was not properly repaid.
    pub fn flash_loan(env: Env, borrower: Address, amount: i128) {
        borrower.require_auth();

        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        let reserve: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Reserve)
            .unwrap_or(0);

        if amount > bal {
            panic!("insufficient pool balance");
        }

        // Deduct the loan.
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(bal - amount));

        // ❌ Callback runs before the invariant check — it can forge a pass.
        Self::run_callback(&env);

        // Invariant check: pool must be whole after callback.
        let post_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        if post_bal < reserve {
            panic!("pool invariant violated: balance below reserve");
        }
    }

    pub fn deposit(env: Env, amount: i128) {
        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(bal + amount));
    }

    pub fn balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0)
    }

    pub fn reserve(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Reserve)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup(reserve: i128) -> (Env, VulnerablePoolClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerablePool);
        let client = VulnerablePoolClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize(&reserve);
        (env, client)
    }

    /// Vulnerable path: callback inflates balance so invariant check passes
    /// even though the borrower never repaid.
    #[test]
    fn test_vulnerable_callback_inflation_bypasses_invariant() {
        let reserve = 1000_i128;
        let (env, client) = setup(reserve);

        let borrower = Address::generate(&env);

        // Enable the inflation callback.
        client.set_callback_inflates(&true);

        // Borrow the full reserve — pool balance drops to 0.
        // The callback inflates it back to reserve before the check.
        client.flash_loan(&borrower, &reserve);

        // Pool "passed" the invariant but the borrower never repaid.
        assert_eq!(client.balance(), reserve, "callback forged a passing check");
    }

    /// Boundary: without callback inflation, an unrepaid loan must fail.
    #[test]
    fn test_unrepaid_loan_fails_without_inflation() {
        let reserve = 1000_i128;
        let (env, client) = setup(reserve);

        let borrower = Address::generate(&env);
        client.set_callback_inflates(&false);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.flash_loan(&borrower, &reserve);
        }));
        assert!(result.is_err(), "unrepaid loan must violate invariant");
    }

    /// Secure path: callback inflation must not satisfy the snapshot-based check.
    #[test]
    fn test_secure_rejects_callback_inflation() {
        use crate::secure::SecurePoolClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecurePool);
        let client = SecurePoolClient::new(&env, &id);
        env.mock_all_auths();

        let reserve = 1000_i128;
        client.initialize(&reserve);

        let borrower = Address::generate(&env);
        client.set_callback_inflates(&true);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.flash_loan(&borrower, &reserve);
        }));
        assert!(
            result.is_err(),
            "secure pool must reject even with callback inflation"
        );
        // Balance was restored to reserve by the callback, but the loan still failed.
        // The pool balance reflects the callback deposit (reserve) but the tx panicked,
        // so in a real environment state would be rolled back. Here we just confirm panic.
    }

    /// Secure path: a borrower who genuinely repays passes the invariant.
    #[test]
    fn test_secure_genuine_repayment_passes() {
        use crate::secure::SecurePoolClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecurePool);
        let client = SecurePoolClient::new(&env, &id);
        env.mock_all_auths();

        let reserve = 1000_i128;
        client.initialize(&reserve);

        // Deposit extra so the pool has more than the reserve.
        client.deposit(&500);
        assert_eq!(client.balance(), 1500);

        let borrower = Address::generate(&env);
        client.set_callback_inflates(&false);

        // Borrow 500 — pool still has 1000 (== reserve) after deduction.
        client.flash_loan(&borrower, &500);
        assert_eq!(client.balance(), 1000);
    }
}
