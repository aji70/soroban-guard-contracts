//! VULNERABLE: Multi-Asset Vault — Asset Key Collision
//!
//! A multi-asset vault that stores all balances in persistent storage keyed
//! **only** by the user's address.  Because the asset address is not included
//! in the key, depositing two different assets for the same user writes to the
//! same storage slot.  The second deposit silently overwrites the first,
//! causing the user to lose their balance for the first asset.
//!
//! VULNERABILITY: the storage key is `&user` alone.  Any two assets deposited
//! by the same user share one slot — the later write clobbers the earlier one.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

pub mod secure;

#[contract]
pub struct AssetKeyCollisionContract;

#[contractimpl]
impl AssetKeyCollisionContract {
    /// Deposit `amount` of `asset` for `user`.
    ///
    /// # Vulnerability
    /// The storage key is only `&user`.  The `asset` address is ignored when
    /// forming the key, so all assets for the same user share one slot.
    /// Depositing asset B after asset A overwrites asset A's balance.
    pub fn deposit(env: Env, user: Address, _asset: Address, amount: i128) {
        user.require_auth();
        // ❌ Key is only the user address — asset address is not included.
        let bal: i128 = env.storage().persistent().get(&user).unwrap_or(0);
        env.storage().persistent().set(&user, &(bal + amount));
    }

    /// Return the stored balance for `user` (ignores `asset` — same bug).
    pub fn balance(env: Env, user: Address, _asset: Address) -> i128 {
        // ❌ Same flat key — cannot distinguish per-asset balances.
        env.storage().persistent().get(&user).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, AssetKeyCollisionContractClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, AssetKeyCollisionContract);
        let client = AssetKeyCollisionContractClient::new(&env, &id);
        (env, client)
    }

    // ── bug demonstration ───────────────────────────────────────────────────

    /// Depositing asset A then asset B for the same user results in only asset
    /// B's balance being stored — asset A's balance is silently overwritten.
    #[test]
    fn test_second_deposit_overwrites_first() {
        let (env, client) = setup();
        let user = Address::generate(&env);
        let asset_a = Address::generate(&env);
        let asset_b = Address::generate(&env);

        client.deposit(&user, &asset_a, &1000);
        client.deposit(&user, &asset_b, &500);

        // ❌ Both reads return the same slot — only the last write survives.
        // asset_a balance should be 1000 but the slot now holds 1500 (0+500
        // accumulated on top of the overwritten 1000).
        let stored = client.balance(&user, &asset_a);
        // The slot holds 1500, not 1000 — asset A's independent balance is lost.
        assert_eq!(stored, 1500, "bug: asset_a balance was overwritten by asset_b deposit");
        // asset_b returns the same shared slot value, not its own 500.
        assert_eq!(client.balance(&user, &asset_b), 1500);
    }

    // ── secure version ──────────────────────────────────────────────────────

    /// After the fix, both asset balances are stored and retrievable
    /// independently — depositing asset B does not affect asset A's balance.
    #[test]
    fn test_secure_both_balances_independent() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let user = Address::generate(&env);
        let asset_a = Address::generate(&env);
        let asset_b = Address::generate(&env);

        client.deposit(&user, &asset_a, &1000);
        client.deposit(&user, &asset_b, &500);

        // ✅ Composite key (user, asset) — each asset has its own slot.
        assert_eq!(client.balance(&user, &asset_a), 1000);
        assert_eq!(client.balance(&user, &asset_b), 500);
    }

    /// Two different users depositing the same asset do not interfere with
    /// each other (works in both vulnerable and secure versions because the
    /// user address differs, but verified here against the secure contract).
    #[test]
    fn test_secure_different_users_do_not_interfere() {
        use crate::secure::SecureVaultClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureVault);
        let client = SecureVaultClient::new(&env, &id);

        let user1 = Address::generate(&env);
        let user2 = Address::generate(&env);
        let asset = Address::generate(&env);

        client.deposit(&user1, &asset, &300);
        client.deposit(&user2, &asset, &700);

        // ✅ Different users — slots are independent.
        assert_eq!(client.balance(&user1, &asset), 300);
        assert_eq!(client.balance(&user2, &asset), 700);
    }
}
