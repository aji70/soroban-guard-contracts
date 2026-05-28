//! VULNERABLE: Even-Number Median Bias
//!
//! A median oracle with an even number of price sources always picks the lower
//! of the two middle values. An attacker controlling one source can push the
//! lower-middle value down, biasing the median at liquidation boundaries.
//!
//! VULNERABILITY: Even-source median selects the lower middle value instead of
//! averaging or requiring an odd quorum.
//!
//! SEVERITY: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Vec};

pub mod secure;

#[contract]
pub struct EvenMedianBias;

#[contractimpl]
impl EvenMedianBias {
    /// ❌ VULNERABLE: sorts prices and returns the lower middle element when the
    /// count is even. An attacker can bias the result downward.
    pub fn median_vulnerable(env: Env, mut prices: Vec<i128>) -> i128 {
        let n = prices.len();
        assert!(n > 0, "no prices");

        // Simple insertion sort (no_std friendly).
        for i in 1..n {
            let mut j = i;
            while j > 0 && prices.get(j - 1).unwrap() > prices.get(j).unwrap() {
                let a = prices.get(j - 1).unwrap();
                let b = prices.get(j).unwrap();
                prices.set(j - 1, b);
                prices.set(j, a);
                j -= 1;
            }
        }

        // BUG: for even n, picks the lower middle value (index n/2 - 1).
        prices.get(n / 2 - 1).unwrap()
    }

    /// Demonstrate the unsafe path: four prices around a threshold.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) -> i128 {
        let _ = actor;
        // Prices: 90, 95, 105, 110 — lower middle = 95, upper middle = 105.
        let mut prices = Vec::new(&env);
        prices.push_back(110_i128);
        prices.push_back(90_i128);
        prices.push_back(105_i128);
        prices.push_back(95_i128);
        let price = Self::median_vulnerable(env, prices);
        price * amount
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, Vec};

    fn make_prices(env: &Env, vals: &[i128]) -> Vec<i128> {
        let mut v = Vec::new(env);
        for &x in vals {
            v.push_back(x);
        }
        v
    }

    /// Vulnerable: four prices around threshold 100 — lower middle (95) is returned.
    #[test]
    fn test_vulnerable_lower_middle_selected() {
        let env = Env::default();
        let id = env.register_contract(None, EvenMedianBias);
        let client = EvenMedianBiasClient::new(&env, &id);

        // Sorted: 90, 95, 105, 110 — lower middle = 95.
        let prices = make_prices(&env, &[110, 90, 105, 95]);
        let median = client.median_vulnerable(&prices);
        assert_eq!(median, 95); // ❌ biased downward
    }

    /// Boundary: attacker pushes one source to 80 — lower middle drops to 80.
    #[test]
    fn test_vulnerable_attacker_biases_lower_middle() {
        let env = Env::default();
        let id = env.register_contract(None, EvenMedianBias);
        let client = EvenMedianBiasClient::new(&env, &id);

        // Attacker controls one source: 80 instead of 90.
        // Sorted: 80, 95, 105, 110 — lower middle = 95 → still 95.
        // Push harder: 80, 85, 105, 110 — lower middle = 85.
        let prices = make_prices(&env, &[110, 85, 105, 80]);
        let median = client.median_vulnerable(&prices);
        assert_eq!(median, 85); // ❌ attacker successfully biased median below 100
    }

    /// Demonstrate vulnerable_entry returns biased collateral value.
    #[test]
    fn test_vulnerable_entry_biased_collateral() {
        let env = Env::default();
        let id = env.register_contract(None, EvenMedianBias);
        let client = EvenMedianBiasClient::new(&env, &id);
        let actor = Address::generate(&env);
        env.mock_all_auths();

        // Lower middle of [90,95,105,110] = 95; 10 units → 950.
        let collateral = client.vulnerable_entry(&actor, &10_i128);
        assert_eq!(collateral, 950); // ❌ biased lower than true median (100)
    }

    /// Secure: odd number of feeds — unambiguous median.
    #[test]
    fn test_secure_odd_count_unambiguous() {
        use crate::secure::SecureMedianClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMedian);
        let client = SecureMedianClient::new(&env, &id);

        // Five prices: 90, 95, 100, 105, 110 — median = 100.
        let prices = make_prices(&env, &[110, 90, 105, 95, 100]);
        let median = client.median(&prices);
        assert_eq!(median, 100); // ✅ unbiased
    }

    /// Secure: even count is rejected.
    #[test]
    #[should_panic(expected = "even feed count")]
    fn test_secure_rejects_even_count() {
        use crate::secure::SecureMedianClient;
        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMedian);
        let client = SecureMedianClient::new(&env, &id);

        let prices = make_prices(&env, &[90, 95, 105, 110]);
        client.median(&prices); // ✅ must panic
    }
}
