//! SECURE: Delete With Tombstone — Stale-Approval Replay Prevention
//!
//! On deletion a tombstone is written that records the highest nonce seen.
//! Any subsequent `approve_entry` whose nonce is ≤ the tombstone nonce is
//! rejected, preventing stale approvals from recreating deleted entries.

use super::{verify_approval, DataKey};
use soroban_sdk::{contract, contractimpl, symbol_short, Bytes, BytesN, Env};

#[contract]
pub struct SecureRegistry;

#[contractimpl]
impl SecureRegistry {
    /// Approve (create/update) an entry.
    /// ✅ Checks tombstone nonce before accepting the approval.
    pub fn approve_entry(env: Env, payload: Bytes, nonce: u32, sig: BytesN<32>) {
        let mut msg = payload.clone();
        msg.extend_from_slice(&nonce.to_le_bytes());
        verify_approval(&env, &msg, &sig);

        // ✅ Reject if nonce is at or below the tombstone left by a prior delete.
        let tombstone_key = DataKey::Tombstone(payload.clone());
        let tombstone: u32 = env
            .storage()
            .persistent()
            .get(&tombstone_key)
            .unwrap_or(0);
        if nonce <= tombstone {
            panic!("stale approval");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Entry(payload.clone()), &nonce);

        env.events()
            .publish((symbol_short!("approved"),), payload);
    }

    /// Delete an entry and write a tombstone preserving the deletion nonce.
    /// ✅ Tombstone prevents any approval with nonce ≤ deletion nonce.
    pub fn delete_entry(env: Env, payload: Bytes) {
        let entry_key = DataKey::Entry(payload.clone());
        let current_nonce: u32 = env
            .storage()
            .persistent()
            .get(&entry_key)
            .unwrap_or(0);

        // ✅ Soft delete: replace live entry with tombstone.
        env.storage().persistent().remove(&entry_key);
        env.storage()
            .persistent()
            .set(&DataKey::Tombstone(payload.clone()), &current_nonce);

        env.events()
            .publish((symbol_short!("deleted"),), payload);
    }

    /// Returns the stored nonce for a live entry, or None if absent/deleted.
    pub fn get_entry(env: Env, payload: Bytes) -> Option<u32> {
        env.storage()
            .persistent()
            .get(&DataKey::Entry(payload))
    }
}
