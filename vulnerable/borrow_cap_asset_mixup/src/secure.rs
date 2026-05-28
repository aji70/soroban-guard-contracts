//! SECURE: Per-Asset Borrow Caps and Independent Tracking
//!
//! Each asset's borrow cap and total borrowed are stored with the asset address
//! as part of the key, ensuring independent enforcement per asset.

use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    BorrowCap(Address),      // ✅ SECURE: Cap keyed by asset
    TotalBorrowed(Address),  // ✅ SECURE: Counter keyed by asset
}

#[contracttype]
#[derive(Clone)]
pub struct BorrowResult {
    pub amount: i128,
    pub total_borrowed: i128,
}

#[contract]
pub struct SecureLending;

#[contractimpl]
impl SecureLending {
    /// Initialize borrow cap for a specific asset.
    pub fn set_borrow_cap(env: Env, asset: Address, cap: i128) {
        // ✅ SECURE: cap is stored under per-asset key.
        env.storage()
            .persistent()
            .set(&DataKey::BorrowCap(asset.clone()), &cap);
        env.events()
            .publish((symbol_short!("cap"),), (asset, cap));
    }

    /// Get the borrow cap for a specific asset.
    pub fn get_borrow_cap(env: Env, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::BorrowCap(asset))
            .unwrap_or(0)
    }

    /// Get total borrowed for a specific asset.
    pub fn get_total_borrowed(env: Env, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalBorrowed(asset))
            .unwrap_or(0)
    }

    /// ✅ SECURE: Borrow from a specific asset with independent cap enforcement.
    pub fn borrow(env: Env, asset: Address, amount: i128) -> BorrowResult {
        let cap = env
            .storage()
            .persistent()
            .get(&DataKey::BorrowCap(asset.clone()))
            .unwrap_or(i128::MAX);

        let total: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalBorrowed(asset.clone()))
            .unwrap_or(0);

        // ✅ SECURE: Each asset's cap is checked independently.
        let new_total = total + amount;
        assert!(new_total <= cap, "borrow exceeds per-asset cap");

        env.storage()
            .persistent()
            .set(&DataKey::TotalBorrowed(asset.clone()), &new_total);

        env.events()
            .publish((symbol_short!("borrow"),), (asset, amount, new_total));

        BorrowResult {
            amount,
            total_borrowed: new_total,
        }
    }
}
