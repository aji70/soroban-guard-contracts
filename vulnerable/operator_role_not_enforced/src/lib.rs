//! VULNERABLE: Operator Role is Read but Never Enforced
//!
//! A maintenance contract that stores an operator address for privileged actions
//! but the protected function reads the role and continues execution even when
//! the caller is not the operator. This makes the role storage decorative and
//! exposes privileged actions to any caller.
//!
//! VULNERABILITY: `emergency_withdraw()` reads the operator address from storage
//! but never asserts that the caller matches it — the role check is silently
//! ignored and any address can drain the contract.
//!
//! SECURE MIRROR: `secure::SecureVault` asserts `caller == operator` before
//! executing privileged state changes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Operator,
    Balance,
}

// ── Vulnerable vault ──────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Initialize the vault with an operator address.
    pub fn init(env: Env, operator: Address) {
        assert!(
            !env.storage().persistent().has(&DataKey::Operator),
            "already initialized"
        );
        env.storage()
            .persistent()
            .set(&DataKey::Operator, &operator);
    }

    /// Deposit funds into the vault.
    pub fn deposit(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(current + amount));
    }

    /// Emergency withdraw — intended to be operator-only.
    ///
    /// ❌ BUG: Reads the operator address but never enforces that the caller
    ///    matches it. Any address can call this and drain the vault.
    pub fn emergency_withdraw(env: Env, caller: Address, amount: i128) {
        caller.require_auth();

        // ❌ Role lookup result is ignored — no assertion that caller == operator.
        let _operator: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("not initialized");

        // Privileged state change proceeds without role enforcement.
        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        assert!(balance >= amount, "insufficient balance");
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(balance - amount));
    }

    pub fn balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0)
    }

    pub fn operator(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("not initialized")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableVaultClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &id);
        let operator = Address::generate(&env);
        let attacker = Address::generate(&env);
        client.init(&operator);
        client.deposit(&operator, &1000);
        (env, client, operator, attacker)
    }

    /// Non-operator calls emergency_withdraw and succeeds — demonstrates the bug.
    /// The role flag was read but never enforced.
    #[test]
    fn test_non_operator_can_drain_vault() {
        let (_env, client, operator, attacker) = setup();

        // Verify the attacker is NOT the operator.
        assert_ne!(attacker, operator);

        // ❌ Attacker calls emergency_withdraw and it succeeds.
        client.emergency_withdraw(&attacker, &500);

        // Vault was drained by a non-operator — this is the vulnerability.
        assert_eq!(client.balance(), 500);
    }

    /// Operator can also call emergency_withdraw (expected behavior).
    #[test]
    fn test_operator_can_withdraw() {
        let (_env, client, operator, _attacker) = setup();
        client.emergency_withdraw(&operator, &300);
        assert_eq!(client.balance(), 700);
    }
}
