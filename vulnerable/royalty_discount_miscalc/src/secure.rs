use super::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Env};

#[contract]
pub struct SecureMarketplace;

#[contractimpl]
impl SecureMarketplace {
    /// SECURE: royalty base is the gross `sale_price` before any rebates.
    /// The rebate is a buyer-side discount that does not reduce the creator's share.
    pub fn settle(env: Env, sale_price: i128, rebate: i128, royalty_bps: i128) -> i128 {
        if sale_price <= 0 {
            panic!("sale_price must be positive");
        }
        if rebate < 0 || rebate >= sale_price {
            panic!("invalid rebate");
        }
        if royalty_bps < 0 || royalty_bps > 10_000 {
            panic!("royalty_bps out of range");
        }

        // ✅ Royalty is computed on the gross sale price — rebate does not affect creator.
        let royalty = sale_price * royalty_bps / 10_000;
        // Seller receives sale_price minus royalty, then the rebate is deducted from that.
        let seller_proceeds = sale_price - royalty - rebate;

        let prev_royalty: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::CreatorRoyalty)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::CreatorRoyalty, &(prev_royalty + royalty));

        let prev_proceeds: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::SellerProceeds)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::SellerProceeds, &(prev_proceeds + seller_proceeds));

        env.events()
            .publish((symbol_short!("settled"),), (sale_price, rebate, royalty));

        royalty
    }

    pub fn creator_royalty(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CreatorRoyalty)
            .unwrap_or(0)
    }

    pub fn seller_proceeds(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::SellerProceeds)
            .unwrap_or(0)
    }
}
