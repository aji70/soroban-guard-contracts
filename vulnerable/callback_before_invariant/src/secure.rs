use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecurePool;

#[contractimpl]
impl SecurePool {
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

    pub fn set_callback_inflates(env: Env, inflates: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::CallbackInflates, &inflates);
    }

    fn run_callback(env: &Env) {
        let inflates: bool = env
            .storage()
            .persistent()
            .get(&DataKey::CallbackInflates)
            .unwrap_or(false);
        if inflates {
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
            if bal < reserve {
                env.storage().persistent().set(&DataKey::Balance, &reserve);
            }
        }
    }

    /// SECURE: snapshots the required post-loan balance *before* the callback,
    /// then validates against that immutable snapshot. Callback-driven inflation
    /// cannot satisfy a check that was already fixed before the callback ran.
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

        // ✅ Snapshot the required post-loan balance before any external call.
        let required_after = bal
            .checked_sub(amount)
            .expect("underflow")
            .max(reserve);

        // Deduct the loan.
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(bal - amount));

        // Run the callback (may attempt to inflate balance).
        Self::run_callback(&env);

        // ✅ Validate against the pre-callback snapshot — inflation is irrelevant.
        // The check is: the balance *before* the callback deduction must have been
        // enough to cover the reserve after lending. We enforce that the loan amount
        // does not reduce the pool below reserve.
        if bal - amount < reserve {
            panic!("pool invariant violated: loan would breach reserve");
        }

        // Ignore any callback-inflated balance — the invariant is already decided.
        let _ = required_after;
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
