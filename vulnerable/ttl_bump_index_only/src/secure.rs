//! SECURE mirror: TTL refresh bumps both the index and the record key.
//!
//! Fixes the vulnerability in `VulnerableRegistry`:
//! - ✅ `refresh` calls `extend_ttl` on both `IndexEntry` and `RecordEntry`
//!   so the two keys always expire together.

use crate::{AccountRecord, DataKey, TTL_EXTEND_TO, TTL_THRESHOLD};
use soroban_sdk::{contract, contractimpl, Address, Env, String};

/// Extend TTL for a single persistent key.
fn bump(env: &Env, key: &DataKey) {
    env.storage()
        .persistent()
        .extend_ttl(key, TTL_THRESHOLD, TTL_EXTEND_TO);
}

#[contract]
pub struct SecureRegistry;

#[contractimpl]
impl SecureRegistry {
    pub fn register(env: Env, account: Address, data: String) {
        account.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::IndexEntry(account.clone()), &true);
        env.storage().persistent().set(
            &DataKey::RecordEntry(account.clone()),
            &AccountRecord {
                owner: account.clone(),
                data,
            },
        );
    }

    /// ✅ Refreshes TTL for both the index entry and the record entry.
    pub fn refresh(env: Env, account: Address) {
        // ✅ Both keys are bumped together so they expire at the same time.
        bump(&env, &DataKey::IndexEntry(account.clone()));
        bump(&env, &DataKey::RecordEntry(account.clone()));
    }

    pub fn get_record(env: Env, account: Address) -> AccountRecord {
        let indexed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::IndexEntry(account.clone()))
            .unwrap_or(false);
        if !indexed {
            panic!("account not registered");
        }
        env.storage()
            .persistent()
            .get(&DataKey::RecordEntry(account))
            .expect("record not found")
    }

    pub fn is_indexed(env: Env, account: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::IndexEntry(account))
            .unwrap_or(false)
    }
}
