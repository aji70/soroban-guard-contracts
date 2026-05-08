//! SECURE: Slippage Protection in Token Swap
//!
//! Identical AMM logic but `swap` requires a `min_amount_out` argument and
//! panics with `"slippage exceeded"` when the calculated output falls below it.

use super::{apply_swap, calculate_out};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureAmm;

#[contractimpl]
impl SecureAmm {
    pub fn init(env: Env, reserve_a: i128, reserve_b: i128) {
        env.storage()
            .persistent()
            .set(&super::DataKey::ReserveA, &reserve_a);
        env.storage()
            .persistent()
            .set(&super::DataKey::ReserveB, &reserve_b);
    }

    /// Swap `amount_in` of token A for token B.
    ///
    /// ✅ Panics if `amount_out < min_amount_out` — protects against sandwich
    ///    attacks and unexpected price impact.
    pub fn swap(env: Env, user: Address, amount_in: i128, min_amount_out: i128) -> i128 {
        user.require_auth();
        let amount_out = calculate_out(&env, amount_in);
        // ✅ Slippage guard.
        assert!(amount_out >= min_amount_out, "slippage exceeded");
        apply_swap(&env, amount_in, amount_out);
        amount_out
    }

    pub fn reserve_a(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&super::DataKey::ReserveA)
            .unwrap_or(0)
    }

    pub fn reserve_b(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&super::DataKey::ReserveB)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_balanced() -> (Env, SecureAmmClient<'static>, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureAmm);
        let client = SecureAmmClient::new(&env, &id);
        client.init(&1000, &1000);
        let user = Address::generate(&env);
        (env, client, user)
    }

    /// Normal swap with a reasonable min_out succeeds.
    #[test]
    fn test_secure_normal_swap_succeeds() {
        let (_env, client, user) = setup_balanced();
        // Expect ~90, set min to 85 to allow small rounding.
        let out = client.swap(&user, &100, &85);
        assert_eq!(out, 90);
    }

    /// After pool manipulation, secure swap panics — victim is protected.
    #[test]
    #[should_panic(expected = "slippage exceeded")]
    fn test_secure_rejects_manipulated_pool() {
        let (env, client, user) = setup_balanced();
        let attacker = Address::generate(&env);

        // Attacker front-runs: skews the pool.
        client.swap(&attacker, &9000, &0);

        // Victim sets min_out=85 (fair price expectation) — must panic.
        client.swap(&user, &100, &85);
    }
}
