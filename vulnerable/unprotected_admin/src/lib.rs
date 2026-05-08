//! VULNERABLE: Unprotected Admin Functions
//!
//! An escrow contract with `set_admin()` and `upgrade()` functions that
//! perform no caller verification. Any account can hijack admin privileges
//! or replace the contract's WASM entirely.
//!
//! VULNERABILITY: `set_admin` and `upgrade` never call `require_auth` on the
//! current admin, so they are callable by anyone.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, BytesN, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    Escrow(Address), // depositor -> locked amount
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    /// One-time initialisation — stores `admin` and guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: no check that the caller is the current admin.
    /// Anyone can call this and become the new admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        // ❌ Missing: let admin: Address = env.storage().persistent().get(&DataKey::Admin).unwrap();
        //             admin.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &new_admin);
    }

    /// VULNERABLE: no auth check before replacing contract WASM.
    /// Anyone can upgrade the contract to arbitrary bytecode.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        // ❌ Missing: admin.require_auth();
        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    /// Deposit `amount` into the escrow for `depositor`. Requires depositor auth.
    pub fn deposit(env: Env, depositor: Address, amount: i128) {
        depositor.require_auth();
        let key = DataKey::Escrow(depositor.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&DataKey::Admin).expect("admin not initialized")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_initialize_sets_admin() {
        let env = Env::default();
        let contract_id = env.register_contract(None, EscrowContract);
        let client = EscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        client.initialize(&admin);
        assert_eq!(client.get_admin(), admin);
    }

    /// Demonstrates the vulnerability: anyone can replace the admin.
    #[test]
    fn test_set_admin_requires_no_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, EscrowContract);
        let client = EscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.initialize(&admin);

        // No auth mocked — contract never checks who is calling.
        client.set_admin(&attacker);
        assert_eq!(client.get_admin(), attacker);
    }

    #[test]
    fn test_deposit_requires_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, EscrowContract);
        let client = EscrowContractClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let depositor = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&admin);
        client.deposit(&depositor, &500);
    }
}
