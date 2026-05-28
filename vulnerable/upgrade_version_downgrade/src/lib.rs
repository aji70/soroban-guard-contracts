//! VULNERABLE: Upgrade Accepts Lower Implementation Version
//!
//! The upgrade path stores the new implementation version without comparing it
//! to the currently installed version. Governance can downgrade to old code.

#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, BytesN, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    ImplHash,
    Version,
}

fn version(env: &Env) -> u32 {
    env.storage()
        .persistent()
        .get(&DataKey::Version)
        .unwrap_or(0)
}

fn set_version(env: &Env, new_version: u32) {
    env.storage()
        .persistent()
        .set(&DataKey::Version, &new_version);
}

fn set_hash(env: &Env, wasm_hash: &BytesN<32>) {
    env.storage()
        .persistent()
        .set(&DataKey::ImplHash, wasm_hash);
}

#[contract]
pub struct UpgradeVersionDowngrade;

#[contractimpl]
impl UpgradeVersionDowngrade {
    pub fn init(env: Env, version: u32, wasm_hash: BytesN<32>) {
        set_version(&env, version);
        set_hash(&env, &wasm_hash);
    }

    pub fn upgrade(env: Env, new_version: u32, new_wasm_hash: BytesN<32>) {
        // VULNERABLE: no monotonic version check before accepting the upgrade.
        set_version(&env, new_version);
        set_hash(&env, &new_wasm_hash);
    }

    pub fn current_version(env: Env) -> u32 {
        version(&env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure::{SecureUpgradeVersion, SecureUpgradeVersionClient};
    use soroban_sdk::{BytesN, Env};

    fn hash(env: &Env, byte: u8) -> BytesN<32> {
        BytesN::from_array(env, &[byte; 32])
    }

    #[test]
    fn vulnerable_accepts_version_downgrade() {
        let env = Env::default();
        let id = env.register_contract(None, UpgradeVersionDowngrade);
        let client = UpgradeVersionDowngradeClient::new(&env, &id);

        client.init(&3, &hash(&env, 3));
        client.upgrade(&2, &hash(&env, 2));

        assert_eq!(client.current_version(), 2);
    }

    #[test]
    #[should_panic(expected = "version must increase")]
    fn secure_rejects_lower_version() {
        let env = Env::default();
        let id = env.register_contract(None, SecureUpgradeVersion);
        let client = SecureUpgradeVersionClient::new(&env, &id);

        client.init(&3, &hash(&env, 3));
        client.upgrade(&2, &hash(&env, 2));
    }
}
