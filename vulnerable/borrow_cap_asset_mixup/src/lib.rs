//! VULNERABLE: Borrow Cap Is Global but Not Enforced Per Asset
//!
//! A lending protocol with per-asset borrow caps stored in a single global key,
//! so borrowing asset A increments the counter checked against asset B's cap.
//! One asset's borrowing can consume or bypass limits intended for another.
//!
//! VULNERABILITY: Borrow cap storage keys have no asset address component.
//! A single global DataKey::BorrowCap and DataKey::TotalBorrowed counter
//! is used for all assets.
//!
//! SECURE MIRROR: `secure::SecureLending` keys borrow cap and total borrowed
//! by `(asset_address,)`, ensuring each asset's cap is tracked independently.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    BorrowCap,      // ❌ VULNERABLE: Global cap, not per-asset
    TotalBorrowed,  // ❌ VULNERABLE: Global counter, not per-asset
}

#[contracttype]
#[derive(Clone)]
pub struct BorrowResult {
    pub amount: i128,
    pub total_borrowed: i128,
}

#[contract]
pub struct VulnerableLending;

#[contractimpl]
impl VulnerableLending {
    /// Initialize borrow cap for an asset (but cap is stored globally!).
    pub fn set_borrow_cap(env: Env, _asset: Address, cap: i128) {
        // ❌ VULNERABLE: cap is stored under global key, ignoring asset address.
        env.storage().persistent().set(&DataKey::BorrowCap, &cap);
        env.events()
            .publish((symbol_short!("cap"),), (_asset, cap));
    }

    /// Get the (global) borrow cap.
    pub fn get_borrow_cap(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::BorrowCap)
            .unwrap_or(0)
    }

    /// Get total borrowed (global counter for all assets).
    pub fn get_total_borrowed(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalBorrowed)
            .unwrap_or(0)
    }

    /// ❌ VULNERABLE: Borrow from any asset, but increment global counter.
    /// The cap is checked against the global total, not per-asset.
    pub fn borrow(env: Env, _asset: Address, amount: i128) -> BorrowResult {
        let cap = env
            .storage()
            .persistent()
            .get(&DataKey::BorrowCap)
            .unwrap_or(i128::MAX);

        let total: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalBorrowed)
            .unwrap_or(0);

        // ❌ VULNERABLE: All assets share the same cap and counter.
        let new_total = total + amount;
        assert!(new_total <= cap, "borrow exceeds global cap");

        env.storage()
            .persistent()
            .set(&DataKey::TotalBorrowed, &new_total);

        env.events()
            .publish((symbol_short!("borrow"),), (_asset, amount, new_total));

        BorrowResult {
            amount,
            total_borrowed: new_total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    #[test]
    fn test_different_caps_share_counter() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableLending);
        let client = VulnerableLendingClient::new(&env, &id);
        let asset_a = Address::generate(&env);
        let asset_b = Address::generate(&env);

        // Set different caps for two assets.
        client.set_borrow_cap(&asset_a, &1000);
        assert_eq!(client.get_borrow_cap(), 1000);

        // ❌ Overwrite cap with asset B's (lower) cap.
        client.set_borrow_cap(&asset_b, &500);
        assert_eq!(client.get_borrow_cap(), 500);

        // Borrow 400 of asset A.
        let result_a = client.borrow(&asset_a, &400);
        assert_eq!(result_a.total_borrowed, 400);

        // ❌ Try to borrow 200 of asset B, but it fails!
        // Total becomes 600, which exceeds the global cap of 500.
        let result_b = client.try_borrow(&asset_b, &200);
        assert!(result_b.is_err(), "vulnerable path blocks asset B borrow");
    }

    #[test]
    fn test_boundary_at_global_cap() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableLending);
        let client = VulnerableLendingClient::new(&env, &id);
        let asset_a = Address::generate(&env);
        let asset_b = Address::generate(&env);

        // Set different caps.
        client.set_borrow_cap(&asset_a, &1000);
        client.set_borrow_cap(&asset_b, &500);

        // Borrow up to the global cap (500).
        let result = client.borrow(&asset_a, &500);
        assert_eq!(result.total_borrowed, 500);

        // ❌ Now asset B cannot borrow anything, even 1 unit.
        let result_b = client.try_borrow(&asset_b, &1);
        assert!(result_b.is_err(), "vulnerable path prevents any further borrowing");
    }

    #[test]
    fn test_secure_per_asset_caps() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureLending);
        let client = secure::SecureLendingClient::new(&env, &id);
        let asset_a = Address::generate(&env);
        let asset_b = Address::generate(&env);

        // Set different caps.
        client.set_borrow_cap(&asset_a, &1000);
        client.set_borrow_cap(&asset_b, &500);

        // Borrow 400 of asset A.
        let result_a = client.borrow(&asset_a, &400);
        assert_eq!(result_a.total_borrowed, 400);

        // ✅ Secure path: can borrow up to asset B's cap (500).
        let result_b = client.borrow(&asset_b, &300);
        assert_eq!(result_b.total_borrowed, 300);

        // Try to exceed asset B's cap.
        let result_b_exceed = client.try_borrow(&asset_b, &250);
        assert!(
            result_b_exceed.is_err(),
            "secure path enforces per-asset cap"
        );
    }
}
