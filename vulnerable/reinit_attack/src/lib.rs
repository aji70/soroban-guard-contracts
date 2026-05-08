//! VULNERABLE: Unguarded Re-initialization
//!
//! A vault contract whose `initialize()` sets the admin and treasury balance
//! but performs no re-init guard. Any caller can invoke `initialize()` again
//! after deployment, replacing the admin with an attacker-controlled address
//! and effectively taking over the contract.
//!
//! VULNERABILITY: `initialize` never checks whether the contract has already
//! been initialized, so it can be called repeatedly by anyone.
//!
//! SECURE MIRROR: `unprotected_admin` / `protected_admin` show the correct
//! pattern:
//!   ```rust
//!   if env.storage().persistent().has(&DataKey::Admin) {
//!       panic!("already initialized");
//!   }
//!   ```

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Treasury,
}

#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    /// VULNERABLE: no re-init guard.
    /// Any caller can invoke this again to overwrite the admin.
    pub fn initialize(env: Env, admin: Address, initial_balance: i128) {
        // ❌ Missing:
        // if env.storage().persistent().has(&DataKey::Admin) {
        //     panic!("already initialized");
        // }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage()
            .persistent()
            .set(&DataKey::Treasury, &initial_balance);
    }

    /// Withdraw `amount` from the treasury. Only the stored admin may call this.
    pub fn withdraw(env: Env, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Treasury)
            .unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage()
            .persistent()
            .set(&DataKey::Treasury, &new_balance);
    }

    /// Returns the current admin address. Panics if not initialized.
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }

    /// Returns the current treasury balance, defaulting to 0.
    pub fn get_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Treasury)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env, IntoVal};

    #[test]
    fn test_initialize_sets_admin() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VaultContract);
        let client = VaultContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.initialize(&admin, &1000);

        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_balance(), 1000);
    }

    /// Demonstrates the vulnerability: a second initialize() call succeeds
    /// and overwrites the admin with an attacker-controlled address.
    #[test]
    fn test_reinit_overwrites_admin() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VaultContract);
        let client = VaultContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.initialize(&admin, &1000);
        assert_eq!(client.get_admin(), admin);

        // No auth required — anyone can call initialize() again.
        client.initialize(&attacker, &0);
        assert_eq!(client.get_admin(), attacker);
    }

    /// After re-init the original admin can no longer withdraw; the attacker
    /// now controls the vault.
    #[test]
    #[should_panic]
    fn test_original_admin_loses_access_after_reinit() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VaultContract);
        let client = VaultContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.initialize(&admin, &1000);

        // Attacker hijacks the contract.
        client.initialize(&attacker, &1000);

        // Original admin tries to withdraw — should panic because require_auth
        // will fail: the stored admin is now the attacker's address.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "withdraw",
                args: (500_i128,).into_val(&env),
                sub_invokes: &[],
            },
        }]);
        client.withdraw(&500);
    }
}
