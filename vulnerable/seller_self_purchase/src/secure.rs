use super::DataKey;
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub struct Listing {
    pub seller: Address,
    pub price: i128,
}

#[contract]
pub struct SecureMarketplace;

#[contractimpl]
impl SecureMarketplace {
    pub fn list(env: Env, seller: Address, listing_id: u64, price: i128) {
        seller.require_auth();
        if price <= 0 {
            panic!("price must be positive");
        }
        env.storage().persistent().set(
            &DataKey::Listing(listing_id),
            &Listing { seller, price },
        );
    }

    /// SECURE: rejects self-purchases before minting any rewards.
    pub fn buy(env: Env, buyer: Address, listing_id: u64) -> i128 {
        buyer.require_auth();

        let listing: Listing = env
            .storage()
            .persistent()
            .get(&DataKey::Listing(listing_id))
            .expect("listing not found");

        // ✅ Prevent wash trading — seller cannot buy their own listing.
        if buyer == listing.seller {
            panic!("seller cannot buy their own listing");
        }

        let rewards_key = DataKey::Rewards(buyer.clone());
        let current_rewards: i128 = env
            .storage()
            .persistent()
            .get(&rewards_key)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&rewards_key, &(current_rewards + listing.price));

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
