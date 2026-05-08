use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};
use super::DataKey;

#[contract]
pub struct SecureUpgrade;

#[contractimpl]
impl SecureUpgrade {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: rejects an all-zero WASM hash before calling
    /// update_current_contract_wasm, preventing the contract from being
    /// bricked by an invalid upgrade target.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        // ✅ Reject zero hash — it has no valid WASM on the ledger and would
        // brick the contract if passed to update_current_contract_wasm.
        if new_wasm_hash == BytesN::from_array(&env, &[0u8; 32]) {
            panic!("wasm hash must not be zero");
        }

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized")
    }
}
