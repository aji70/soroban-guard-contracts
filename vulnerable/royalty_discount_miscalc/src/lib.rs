//! VULNERABLE: Royalty Calculation Uses Post-Discount Sale Price
//!
//! A marketplace applies a buyer-specific rebate before computing the
//! creator royalty. The royalty percentage is applied to the net amount
//! after the discount, not the listed sale price. Creators receive less
//! than the agreed percentage of the sale price.
//!
//! VULNERABILITY: `settle` computes `royalty = (sale_price - rebate) * rate / 100`
//! instead of `royalty = sale_price * rate / 100`.
//!
//! SECURE MIRROR: `secure::SecureMarketplace` fixes the royalty base to the
//! gross sale price before any rebates are applied.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Env};

pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Accumulated royalties owed to the creator.
    CreatorRoyalty,
    /// Net proceeds owed to the seller (sale_price - royalty - rebate).
    SellerProceeds,
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableMarketplace;

#[contractimpl]
impl VulnerableMarketplace {
    /// VULNERABLE: royalty base is `sale_price - rebate` (post-discount).
    ///
    /// # Vulnerability
    /// Royalty is computed on the net amount after the buyer rebate.
    /// Impact: creator receives less than the agreed royalty_bps of sale_price.
    ///
    /// `royalty_bps` is in basis points (100 bps = 1%).
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

        // ❌ Royalty base is net amount after rebate — creator is underpaid.
        let net = sale_price - rebate;
        let royalty = net * royalty_bps / 10_000;
        let seller_proceeds = net - royalty;

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::Env;

    /// Vulnerable path: royalty is underpaid when a rebate is applied.
    #[test]
    fn test_vulnerable_royalty_underpaid_with_rebate() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);

        // Sale price: 10_000, rebate: 2_000, royalty: 10% (1_000 bps)
        // Expected royalty on gross: 10_000 * 10% = 1_000
        // Vulnerable royalty on net:  8_000 * 10% = 800  ← underpaid
        let royalty = client.settle(&10_000, &2_000, &1_000);
        assert_eq!(royalty, 800, "vulnerable: royalty computed on post-discount price");
        assert_eq!(client.creator_royalty(), 800);
    }

    /// Boundary: zero rebate means both versions produce the same royalty.
    #[test]
    fn test_zero_rebate_royalty_matches() {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);

        // No rebate — net == sale_price, so both formulas agree.
        let royalty = client.settle(&10_000, &0, &1_000);
        assert_eq!(royalty, 1_000, "zero rebate: royalty must equal 10% of sale price");
    }

    /// Secure path: royalty is computed on gross sale price regardless of rebate.
    #[test]
    fn test_secure_royalty_uses_gross_sale_price() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);

        // Same inputs as the vulnerable test.
        let royalty = client.settle(&10_000, &2_000, &1_000);
        assert_eq!(royalty, 1_000, "secure: royalty must be 10% of gross sale price");
        assert_eq!(client.creator_royalty(), 1_000);
    }

    /// Secure path: seller proceeds are sale_price - royalty - rebate.
    #[test]
    fn test_secure_seller_proceeds_correct() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);

        // sale_price=10_000, rebate=2_000, royalty_bps=1_000 (10%)
        // royalty = 10_000 * 10% = 1_000
        // seller  = 10_000 - 1_000 - 2_000 = 7_000
        client.settle(&10_000, &2_000, &1_000);
        assert_eq!(client.seller_proceeds(), 7_000);
    }
}
