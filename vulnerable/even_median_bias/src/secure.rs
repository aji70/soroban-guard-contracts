//! SECURE mirror: require an odd number of feeds so the median is unambiguous.

use soroban_sdk::{contract, contractimpl, Env, Vec};

#[contract]
pub struct SecureMedian;

#[contractimpl]
impl SecureMedian {
    /// ✅ Panics if feed count is even — forces an odd quorum.
    pub fn median(env: Env, mut prices: Vec<i128>) -> i128 {
        let n = prices.len();
        assert!(n > 0, "no prices");
        assert!(n % 2 == 1, "even feed count");

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

        // Odd n — single unambiguous middle element.
        prices.get(n / 2).unwrap()
    }
}
