//! VULNERABLE: Token Total Supply Not Tracked
//!
//! A token contract with a `MAX_SUPPLY` constant that is never enforced.
//! The `mint` function adds to individual balances without tracking or
//! checking a running total supply, allowing unlimited inflation.
//!
//! VULNERABILITY: No `DataKey::TotalSupply` tracking; `MAX_SUPPLY` is never
//! checked against the actual minted amount.
//! Severity: High
//!
//! Secure mirror: `secure::SecureTokenContract` tracks total supply and
//! rejects mints that would exceed `MAX_SUPPLY`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAX_SUPPLY: i128 = 1_000_000_000;

// ── Storage keys ─────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
    TotalSupply,
}

// ── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableTokenContract;

#[contractimpl]
impl VulnerableTokenContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: mints `amount` to `to` without checking total supply.
    /// `MAX_SUPPLY` is defined but never enforced.
    pub fn mint(env: Env, to: Address, amount: i128) {
        Self::require_admin(&env);
        // ❌ No total supply tracking — MAX_SUPPLY is never enforced.
        let key = DataKey::Balance(to);
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableTokenContract);
        let admin = Address::generate(&env);
        VulnerableTokenContractClient::new(&env, &id).initialize(&admin);
        (env, id, admin)
    }

    /// Admin mints up to MAX_SUPPLY — works.
    #[test]
    fn test_mint_up_to_max_supply_works() {
        let (env, id, _admin) = setup();
        let client = VulnerableTokenContractClient::new(&env, &id);
        let user = Address::generate(&env);

        client.mint(&user, &MAX_SUPPLY);
        assert_eq!(client.balance(&user), MAX_SUPPLY);
    }

    /// DEMONSTRATES VULNERABILITY: admin mints beyond MAX_SUPPLY — succeeds.
    #[test]
    fn test_mint_beyond_max_supply_succeeds_vulnerability() {
        let (env, id, _admin) = setup();
        let client = VulnerableTokenContractClient::new(&env, &id);
        let user = Address::generate(&env);

        // Mint MAX_SUPPLY first, then mint 1 more — should be rejected but isn't.
        client.mint(&user, &MAX_SUPPLY);
        client.mint(&user, &1);

        assert_eq!(
            client.balance(&user),
            MAX_SUPPLY + 1,
            "supply exceeded MAX_SUPPLY — vulnerability confirmed"
        );
    }

    /// Secure version rejects mint that would exceed MAX_SUPPLY.
    #[test]
    #[should_panic(expected = "mint would exceed max supply")]
    fn test_secure_rejects_mint_exceeding_max_supply() {
        use crate::secure::SecureTokenContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTokenContract);
        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let client = SecureTokenContractClient::new(&env, &id);

        client.initialize(&admin);
        client.mint(&user, &MAX_SUPPLY);
        // This should panic.
        client.mint(&user, &1);
    }

    /// total_supply() returns correct value in secure version.
    #[test]
    fn test_secure_total_supply_tracked() {
        use crate::secure::SecureTokenContractClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureTokenContract);
        let admin = Address::generate(&env);
        let user_a = Address::generate(&env);
        let user_b = Address::generate(&env);
        let client = SecureTokenContractClient::new(&env, &id);

        client.initialize(&admin);
        client.mint(&user_a, &500_000_000);
        client.mint(&user_b, &300_000_000);

        assert_eq!(client.total_supply(), 800_000_000);
    }
}
