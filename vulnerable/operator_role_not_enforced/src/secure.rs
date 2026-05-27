//! SECURE: Operator Role is Enforced
//!
//! Identical vault but `emergency_withdraw` asserts that the caller matches
//! the stored operator address before executing privileged state changes.

use soroban_sdk::{contract, contractimpl, Address, Env};
use super::DataKey;

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn init(env: Env, operator: Address) {
        assert!(
            !env.storage().persistent().has(&DataKey::Operator),
            "already initialized"
        );
        env.storage()
            .persistent()
            .set(&DataKey::Operator, &operator);
    }

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

    /// Emergency withdraw — operator-only.
    ///
    /// ✅ Asserts caller == operator before privileged state changes.
    pub fn emergency_withdraw(env: Env, caller: Address, amount: i128) {
        caller.require_auth();

        let operator: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Operator)
            .expect("not initialized");

        // ✅ Enforce the role check.
        assert!(caller == operator, "caller is not the operator");

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

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, SecureVaultClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &id);
        let operator = Address::generate(&env);
        let attacker = Address::generate(&env);
        client.init(&operator);
        client.deposit(&operator, &1000);
        (env, client, operator, attacker)
    }

    /// Operator can call emergency_withdraw — secure version succeeds.
    #[test]
    fn test_secure_operator_can_withdraw() {
        let (_env, client, operator, _attacker) = setup();
        client.emergency_withdraw(&operator, &300);
        assert_eq!(client.balance(), 700);
    }

    /// Non-operator is rejected — secure version panics.
    #[test]
    #[should_panic(expected = "caller is not the operator")]
    fn test_secure_non_operator_rejected() {
        let (_env, client, _operator, attacker) = setup();
        client.emergency_withdraw(&attacker, &500);
    }
}
