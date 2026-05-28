//! SECURE: Upgrade versions must increase monotonically.

use super::{set_hash, set_version, version};
use soroban_sdk::{contract, contractimpl, BytesN, Env};

#[contract]
pub struct SecureUpgradeVersion;

#[contractimpl]
impl SecureUpgradeVersion {
    pub fn init(env: Env, version: u32, wasm_hash: BytesN<32>) {
        set_version(&env, version);
        set_hash(&env, &wasm_hash);
    }

    pub fn upgrade(env: Env, new_version: u32, new_wasm_hash: BytesN<32>) {
        assert!(new_version > version(&env), "version must increase");
        set_version(&env, new_version);
        set_hash(&env, &new_wasm_hash);
    }

    pub fn current_version(env: Env) -> u32 {
        version(&env)
    }
}
