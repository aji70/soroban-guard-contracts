//! VULNERABLE: Storage Key Collision via Predictable Flat Keys
//!
//! A config + per-user balance contract that uses `symbol_short!` for every
//! storage key.  Because `symbol_short!` produces a plain `Symbol` (up to 9
//! printable ASCII chars), any two keys that happen to share the same string
//! value occupy the **same** storage slot — regardless of what type of data
//! was written there first.
//!
//! VULNERABILITY: flat string keys have no type namespace.  A user whose
//! chosen "tag" equals `"admin"` silently overwrites the global admin slot,
//! and vice-versa.  The contract cannot distinguish `Config { admin }` from
//! `u64 { balance }` once both are stored under the same raw symbol.

#![no_std]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env, Symbol};

pub mod secure;

#[contract]
pub struct KeyCollisionContract;

#[contractimpl]
impl KeyCollisionContract {
    /// Store the global admin using the flat key `"admin"`.
    ///
    /// # Vulnerability
    /// Uses a plain `symbol_short!` key with no namespace. Any user tag equal to `"admin"` will
    /// overwrite this slot. Impact: privilege escalation or data corruption.
    pub fn set_admin(env: Env, admin: Address) {
        // ❌ Plain symbol — collides with any user key that is also "admin".
        env.storage()
            .persistent()
            .set(&symbol_short!("admin"), &admin);
    }

    /// Returns the stored admin address, or `None` if not set.
    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&symbol_short!("admin"))
    }

    /// Store a per-user balance under a caller-supplied `tag` symbol.
    ///
    /// VULNERABLE: if `tag == symbol_short!("admin")` the write lands in the
    /// same slot as the global admin, corrupting it.
    pub fn set_balance(env: Env, tag: Symbol, amount: u64) {
        // ❌ No namespace — `tag` can equal any other key in the contract.
        env.storage().persistent().set(&tag, &amount);
    }

    /// Returns the balance stored under `tag`, or `None` if absent.
    pub fn get_balance(env: Env, tag: Symbol) -> Option<u64> {
        env.storage().persistent().get(&tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env};

    fn setup() -> (Env, KeyCollisionContractClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, KeyCollisionContract);
        let client = KeyCollisionContractClient::new(&env, &id);
        (env, client)
    }

    // ── normal operation ────────────────────────────────────────────────────

    #[test]
    fn test_set_and_get_admin() {
        let (env, client) = setup();
        let admin = Address::generate(&env);
        client.set_admin(&admin);
        assert_eq!(client.get_admin(), Some(admin));
    }

    #[test]
    fn test_set_and_get_balance() {
        let (_env, client) = setup();
        client.set_balance(&symbol_short!("alice"), &500_u64);
        assert_eq!(client.get_balance(&symbol_short!("alice")), Some(500));
    }

    // ── collision demonstration ─────────────────────────────────────────────

    /// Writing a balance under the key `"admin"` overwrites the global admin
    /// slot.  When `get_admin` then tries to deserialise a `u64` as an
    /// `Address` the host panics — proving the slot was corrupted.
    #[test]
    #[should_panic]
    fn test_balance_key_collides_with_admin_slot() {
        let (env, client) = setup();

        let real_admin = Address::generate(&env);
        client.set_admin(&real_admin);

        // ❌ Same raw symbol "admin" — clobbers the admin slot with a u64.
        client.set_balance(&symbol_short!("admin"), &9999_u64);

        // Panics: slot now holds u64 bytes, not an Address.
        client.get_admin();
    }

    /// Conversely, set_admin overwrites a balance stored under "admin".
    /// Reading back the balance panics because the slot now holds an Address.
    #[test]
    #[should_panic]
    fn test_admin_write_clobbers_balance_slot() {
        let (env, client) = setup();

        client.set_balance(&symbol_short!("admin"), &42_u64);

        let new_admin = Address::generate(&env);
        // ❌ Same raw symbol "admin" — clobbers the balance slot with an Address.
        client.set_admin(&new_admin);

        // Panics: slot now holds Address bytes, not a u64.
        client.get_balance(&symbol_short!("admin"));
    }

    // ── secure version ──────────────────────────────────────────────────────

    #[test]
    fn test_secure_no_collision() {
        use crate::secure::SecureContractClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureContract);
        let client = SecureContractClient::new(&env, &id);

        let admin = Address::generate(&env);
        client.set_admin(&admin);

        // Even if the user tag string equals "Admin", the typed enum variant
        // DataKey::Balance(tag) is serialised differently from DataKey::Admin,
        // so the slots never overlap.
        let tag = Address::generate(&env);
        client.set_balance(&tag, &777_u64);

        assert_eq!(client.get_admin(), Some(admin));
        assert_eq!(client.get_balance(&tag), Some(777));
    }
}
