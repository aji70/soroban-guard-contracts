//! VULNERABLE: Seller Can Buy Own Listing to Farm Rewards
//!
//! A marketplace mints buyer reward points on every purchase. The `buy`
//! function does not check that the buyer is different from the seller.
//! A seller can list an item and immediately buy it back, farming reward
//! points and inflating volume metrics at zero real cost.
//!
//! VULNERABILITY: `buy` omits a `buyer != seller` guard before minting
//! rewards.
//!
//! SECURE MIRROR: `secure::SecureMarketplace` rejects self-purchases
//! outright, preventing wash trading and reward farming.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

#[contracttype]
#[derive(Clone)]
pub struct Listing {
    pub seller: Address,
    pub price: i128,
}

#[contracttype]
pub enum DataKey {
    Listing(u64),
    /// Reward points balance per address.
    Rewards(Address),
    /// Total volume traded (for wash-trade inflation check).
    TotalVolume,
}

#[contract]
pub struct VulnerableMarketplace;

#[contractimpl]
impl VulnerableMarketplace {
    pub fn list(env: Env, seller: Address, listing_id: u64, price: i128) {
        seller.require_auth();
        if price <= 0 {
            panic!("price must be positive");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Listing(listing_id), &Listing { seller, price });
    }

    /// VULNERABLE: buyer rewards are minted without checking buyer != seller.
    ///
    /// # Vulnerability
    /// Missing `if buyer == listing.seller { panic!(...) }` guard.
    /// Impact: seller can wash trade to farm reward points and inflate volume.
    pub fn buy(env: Env, buyer: Address, listing_id: u64) -> i128 {
        buyer.require_auth();

        let listing: Listing = env
            .storage()
            .persistent()
            .get(&DataKey::Listing(listing_id))
            .expect("listing not found");

        // ❌ Missing: buyer != seller check.

        // Mint reward points to buyer (1 point per unit of price).
        let rewards_key = DataKey::Rewards(buyer.clone());
        let current_rewards: i128 = env
            .storage()
            .persistent()
            .get(&rewards_key)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&rewards_key, &(current_rewards + listing.price));

        // Record volume.
        let vol: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalVolume)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalVolume, &(vol + listing.price));

        env.storage()
            .persistent()
            .remove(&DataKey::Listing(listing_id));

        listing.price
    }

    pub fn rewards(env: Env, addr: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Rewards(addr))
            .unwrap_or(0)
    }

    pub fn total_volume(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalVolume)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableMarketplaceClient<'static>, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        env.mock_all_auths();
        client.list(&seller, &1, &1000);
        (env, client, seller)
    }

    /// Vulnerable path: seller buys own listing and farms rewards.
    #[test]
    fn test_vulnerable_seller_farms_rewards_via_self_purchase() {
        let (_env, client, seller) = setup();

        // Seller buys their own listing.
        client.buy(&seller, &1);

        assert_eq!(
            client.rewards(&seller),
            1000,
            "vulnerable: seller farmed reward points"
        );
        assert_eq!(client.total_volume(), 1000, "volume inflated by wash trade");
    }

    /// Boundary: a legitimate buyer (different address) always earns rewards.
    #[test]
    fn test_legitimate_buyer_earns_rewards() {
        let (env, client, _seller) = setup();
        let buyer = Address::generate(&env);

        client.buy(&buyer, &1);
        assert_eq!(client.rewards(&buyer), 1000);
    }

    /// Secure path: self-purchase must be rejected.
    #[test]
    fn test_secure_rejects_self_purchase() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        env.mock_all_auths();

        client.list(&seller, &1, &1000);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.buy(&seller, &1);
        }));
        assert!(result.is_err(), "secure: self-purchase must be rejected");
        assert_eq!(
            client.rewards(&seller),
            0,
            "no rewards must be minted for self-purchase"
        );
        assert_eq!(client.total_volume(), 0, "volume must not be inflated");
    }

    /// Secure path: legitimate buyer earns rewards normally.
    #[test]
    fn test_secure_legitimate_buyer_earns_rewards() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();

        client.list(&seller, &1, &1000);
        client.buy(&buyer, &1);

        assert_eq!(client.rewards(&buyer), 1000);
        assert_eq!(client.total_volume(), 1000);
    }
}
