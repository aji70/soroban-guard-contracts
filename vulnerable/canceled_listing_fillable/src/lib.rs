//! VULNERABLE: Canceled Listing Remains Fillable by Old Order ID
//!
//! The marketplace uses two separate storage keys: `CanceledOrder(id)` is
//! set by `cancel`, but `fill_order` only reads `ActiveOrder(id)`. Because
//! cancellation never removes the active-order key, a canceled listing can
//! still be purchased.
//!
//! VULNERABILITY: `cancel` writes to `CanceledOrder` while `fill_order`
//! reads `ActiveOrder` — the two keys are never reconciled.
//!
//! SECURE MIRROR: `secure::SecureMarketplace` uses a single canonical
//! `OrderStatus` key that `cancel` sets to `Canceled` and `fill_order`
//! checks before proceeding.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
#[derive(Clone)]
pub struct Order {
    pub seller: Address,
    pub price: i128,
}

#[contracttype]
pub enum DataKey {
    /// Written by `create_order` and read by `fill_order`.
    ActiveOrder(u64),
    /// Written by `cancel` — but `fill_order` never checks this key.
    CanceledOrder(u64),
    /// Tracks fill events for test assertions.
    Filled(u64),
}

#[contract]
pub struct VulnerableMarketplace;

#[contractimpl]
impl VulnerableMarketplace {
    pub fn create_order(env: Env, seller: Address, order_id: u64, price: i128) {
        seller.require_auth();
        if env
            .storage()
            .persistent()
            .has(&DataKey::ActiveOrder(order_id))
        {
            panic!("order already exists");
        }
        env.storage()
            .persistent()
            .set(&DataKey::ActiveOrder(order_id), &Order { seller, price });
    }

    /// VULNERABLE: writes to `CanceledOrder` but leaves `ActiveOrder` intact.
    ///
    /// # Vulnerability
    /// `fill_order` reads `ActiveOrder` and never checks `CanceledOrder`,
    /// so the listing remains purchasable after cancellation.
    pub fn cancel(env: Env, seller: Address, order_id: u64) {
        seller.require_auth();

        let order: Order = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveOrder(order_id))
            .expect("order not found");

        if order.seller != seller {
            panic!("only the seller can cancel");
        }

        // ❌ Sets a separate canceled key but does NOT remove ActiveOrder.
        env.storage()
            .persistent()
            .set(&DataKey::CanceledOrder(order_id), &true);
    }

    /// VULNERABLE: checks only `ActiveOrder`; ignores `CanceledOrder`.
    pub fn fill_order(env: Env, buyer: Address, order_id: u64) -> i128 {
        buyer.require_auth();

        let order: Order = env
            .storage()
            .persistent()
            .get(&DataKey::ActiveOrder(order_id))
            .expect("order not found");

        // ❌ Missing: check that CanceledOrder(order_id) is not set.

        env.storage()
            .persistent()
            .set(&DataKey::Filled(order_id), &true);
        env.storage()
            .persistent()
            .remove(&DataKey::ActiveOrder(order_id));

        order.price
    }

    pub fn is_filled(env: Env, order_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Filled(order_id))
            .unwrap_or(false)
    }

    pub fn is_canceled(env: Env, order_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::CanceledOrder(order_id))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableMarketplaceClient<'static>, Address, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();
        client.create_order(&seller, &1, &500);
        (env, client, seller, buyer)
    }

    /// Vulnerable path: canceled listing is still fillable.
    #[test]
    fn test_vulnerable_canceled_listing_still_fillable() {
        let (_env, client, seller, buyer) = setup();

        client.cancel(&seller, &1);
        assert!(client.is_canceled(&1), "order should be marked canceled");

        // Fill succeeds despite cancellation.
        let price = client.fill_order(&buyer, &1);
        assert_eq!(price, 500);
        assert!(client.is_filled(&1), "vulnerable: canceled order was filled");
    }

    /// Boundary: filling an active (non-canceled) order must always succeed.
    #[test]
    fn test_active_order_can_be_filled() {
        let (_env, client, _seller, buyer) = setup();

        let price = client.fill_order(&buyer, &1);
        assert_eq!(price, 500);
        assert!(client.is_filled(&1));
    }

    /// Secure path: canceled listing must not be fillable.
    #[test]
    fn test_secure_canceled_listing_not_fillable() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();

        client.create_order(&seller, &1, &500);
        client.cancel(&seller, &1);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.fill_order(&buyer, &1);
        }));
        assert!(result.is_err(), "secure: canceled order must not be fillable");
        assert!(!client.is_filled(&1), "order must not be marked filled");
    }

    /// Secure path: active order fills normally.
    #[test]
    fn test_secure_active_order_fills_normally() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();

        client.create_order(&seller, &1, &500);
        let price = client.fill_order(&buyer, &1);
        assert_eq!(price, 500);
        assert!(client.is_filled(&1));
    }
}
