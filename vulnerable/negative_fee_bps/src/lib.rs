//! VULNERABLE: Negative Fee Basis Points
//!
//! A fee contract that stores `fee_bps` as a signed integer and only caps the
//! upper bound. A negative value turns fee collection into a rebate: instead of
//! deducting a fee from the sender, the contract *credits* extra tokens to the
//! recipient, draining the fee pool and inflating balances.
//!
//! VULNERABILITY: `set_fee` accepts any `fee_bps < 0` because only the upper
//! bound (`> 10_000`) is checked. `apply_fee` then computes a negative fee and
//! *adds* it to the recipient's balance rather than subtracting it.
//! SECURE MIRROR: `secure::SecureFeeContract` requires `0 <= fee_bps <= 10_000`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    FeeBps,
    Admin,
    Balance(Address),
}

pub(crate) fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

pub(crate) fn set_balance(env: &Env, account: &Address, val: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &val);
}

#[contract]
pub struct FeeContract;

#[contractimpl]
impl FeeContract {
    pub fn initialize(env: Env, admin: Address, fee_bps: i128) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    /// VULNERABLE: only the upper bound is checked; negative fee_bps is accepted.
    pub fn set_fee(env: Env, fee_bps: i128) {
        let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        admin.require_auth();
        // ❌ Missing lower-bound check: fee_bps < 0 is silently accepted
        if fee_bps > 10_000 {
            panic!("fee_bps exceeds 10000");
        }
        env.storage().persistent().set(&DataKey::FeeBps, &fee_bps);
    }

    /// VULNERABLE: a negative fee_bps produces a negative fee, which is
    /// *subtracted* from the recipient's deduction — i.e. the recipient gains
    /// extra tokens instead of paying a fee.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();
        let fee_bps: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0);
        // ❌ fee is negative when fee_bps < 0; recipient receives amount - fee > amount
        let fee = amount * fee_bps / 10_000;
        let net = amount - fee;
        set_balance(&env, &from, get_balance(&env, &from) - amount);
        set_balance(&env, &to, get_balance(&env, &to) + net);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn current_fee_bps(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::FeeBps)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    // ── Regression: negative fee_bps is accepted and credits the attacker ───

    /// set_fee(-500) succeeds — the lower-bound check is missing.
    #[test]
    fn test_negative_fee_bps_accepted() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, FeeContract);
        let client = FeeContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0);

        client.set_fee(&-500);
        assert_eq!(client.current_fee_bps(), -500);
    }

    /// With fee_bps = -500 (-5%), a transfer of 1000 credits the recipient
    /// 1050 instead of 1000, draining value from the protocol.
    #[test]
    fn test_negative_fee_credits_recipient() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, FeeContract);
        let client = FeeContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1_000);
        client.set_fee(&-500); // -5%
        client.transfer(&alice, &bob, &1_000);

        // fee = 1000 * -500 / 10000 = -50  →  net = 1000 - (-50) = 1050
        assert_eq!(client.balance(&bob), 1_050);
        assert_eq!(client.balance(&alice), 0);
    }

    // ── Boundary: fee_bps = 0 produces no fee ───────────────────────────────

    #[test]
    fn test_zero_fee_bps_no_fee() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, FeeContract);
        let client = FeeContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1_000);
        client.transfer(&alice, &bob, &1_000);
        assert_eq!(client.balance(&bob), 1_000);
    }

    // ── Secure: negative fee_bps is rejected ────────────────────────────────

    #[test]
    #[should_panic]
    fn test_secure_rejects_negative_fee_bps() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureFeeContract);
        let client = secure::SecureFeeContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &0);
        client.set_fee(&-1); // must panic
    }

    /// Secure transfer with a positive fee correctly deducts from the recipient.
    #[test]
    fn test_secure_positive_fee_deducted() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureFeeContract);
        let client = secure::SecureFeeContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin, &500); // 5%

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1_000);
        client.transfer(&alice, &bob, &1_000);

        // fee = 1000 * 500 / 10000 = 50  →  net = 950
        assert_eq!(client.balance(&bob), 950);
        assert_eq!(client.balance(&alice), 0);
    }
}
