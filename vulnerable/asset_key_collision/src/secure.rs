//! SECURE mirror: composite `(user, asset)` key prevents balance collision.
//!
//! A `#[contracttype]` enum variant `Balance(Address, Address)` encodes both
//! the user address and the asset address into the storage key.  Each
//! (user, asset) pair occupies its own slot — deposits for different assets
//! never overwrite each other.

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    /// Composite key: (user, asset) — unique per user-asset pair.
    Balance(Address, Address),
}

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// Deposit `amount` of `asset` for `user`.
    ///
    /// Uses a composite `DataKey::Balance(user, asset)` so each asset has its
    /// own independent storage slot.
    pub fn deposit(env: Env, user: Address, asset: Address, amount: i128) {
        user.require_auth();
        // ✅ Composite key — (user, asset) pair is unique per slot.
        let key = DataKey::Balance(user.clone(), asset.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// Return the balance of `asset` held by `user`.
    pub fn balance(env: Env, user: Address, asset: Address) -> i128 {
        // ✅ Same composite key — reads the correct per-asset slot.
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user, asset))
            .unwrap_or(0)
    }
}
