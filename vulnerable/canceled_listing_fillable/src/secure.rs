use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone, PartialEq)]
pub enum OrderStatus {
    Active,
    Canceled,
    Filled,
}

#[contracttype]
#[derive(Clone)]
pub struct Order {
    pub seller: Address,
    pub price: i128,
}

#[contracttype]
pub enum SecureDataKey {
    Order(u64),
    /// SECURE: single canonical status key checked by every path.
    OrderStatus(u64),
}

#[contract]
pub struct SecureMarketplace;

#[contractimpl]
impl SecureMarketplace {
    pub fn create_order(env: Env, seller: Address, order_id: u64, price: i128) {
        seller.require_auth();
        if env
            .storage()
            .persistent()
            .has(&SecureDataKey::Order(order_id))
        {
            panic!("order already exists");
        }
        env.storage()
            .persistent()
            .set(&SecureDataKey::Order(order_id), &Order { seller, price });
        // ✅ Single status key set at creation.
        env.storage()
            .persistent()
            .set(&SecureDataKey::OrderStatus(order_id), &OrderStatus::Active);
    }

    /// SECURE: updates the canonical status key to Canceled.
    pub fn cancel(env: Env, seller: Address, order_id: u64) {
        seller.require_auth();

        let order: Order = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Order(order_id))
            .expect("order not found");

        if order.seller != seller {
            panic!("only the seller can cancel");
        }

        let status: OrderStatus = env
            .storage()
            .persistent()
            .get(&SecureDataKey::OrderStatus(order_id))
            .expect("status not found");

        if status != OrderStatus::Active {
            panic!("order is not active");
        }

        // ✅ Same key that fill_order checks.
        env.storage()
            .persistent()
            .set(&SecureDataKey::OrderStatus(order_id), &OrderStatus::Canceled);
    }

    /// SECURE: checks the canonical status before filling.
    pub fn fill_order(env: Env, buyer: Address, order_id: u64) -> i128 {
        buyer.require_auth();

        let status: OrderStatus = env
            .storage()
            .persistent()
            .get(&SecureDataKey::OrderStatus(order_id))
            .expect("order not found");

        // ✅ Rejects anything that is not Active.
        if status != OrderStatus::Active {
            panic!("order is not active");
        }

        let order: Order = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Order(order_id))
            .expect("order data missing");

        env.storage()
            .persistent()
            .set(&SecureDataKey::OrderStatus(order_id), &OrderStatus::Filled);

        order.price
    }

    pub fn is_filled(env: Env, order_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&SecureDataKey::OrderStatus(order_id))
            .map(|s: OrderStatus| s == OrderStatus::Filled)
            .unwrap_or(false)
    }

    pub fn is_canceled(env: Env, order_id: u64) -> bool {
        env.storage()
            .persistent()
            .get(&SecureDataKey::OrderStatus(order_id))
            .map(|s: OrderStatus| s == OrderStatus::Canceled)
            .unwrap_or(false)
    }
}
