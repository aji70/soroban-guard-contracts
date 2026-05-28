use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub struct Listing {
    pub seller: Address,
    pub price: i128,
    pub royalty_bps: i128,
    /// SECURE: recipient is snapshotted at listing creation time.
    pub royalty_recipient: Address,
}

#[contracttype]
pub enum SecureDataKey {
    /// Live royalty recipient — only used when creating new listings.
    RoyaltyRecipient,
    Listing(u64),
    RoyaltiesPaid,
}

#[contract]
pub struct SecureMarketplace;

#[contractimpl]
impl SecureMarketplace {
    /// Set the royalty recipient. Only affects future listings.
    pub fn set_royalty_recipient(env: Env, seller: Address, recipient: Address) {
        seller.require_auth();
        env.storage()
            .persistent()
            .set(&SecureDataKey::RoyaltyRecipient, &recipient);
    }

    /// SECURE: snapshot the current royalty recipient into the listing.
    pub fn create_listing(
        env: Env,
        seller: Address,
        listing_id: u64,
        price: i128,
        royalty_bps: i128,
    ) {
        seller.require_auth();
        if royalty_bps < 0 || royalty_bps > 10_000 {
            panic!("invalid royalty bps");
        }
        // ✅ Capture recipient at listing time — immutable for this listing.
        let royalty_recipient: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::RoyaltyRecipient)
            .expect("royalty recipient not configured");

        env.storage().persistent().set(
            &SecureDataKey::Listing(listing_id),
            &Listing {
                seller,
                price,
                royalty_bps,
                royalty_recipient,
            },
        );
    }

    /// SECURE: reads royalty recipient from the listing snapshot, not live config.
    pub fn settle(env: Env, buyer: Address, listing_id: u64) -> Address {
        buyer.require_auth();

        let listing: Listing = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Listing(listing_id))
            .expect("listing not found");

        // ✅ Use the snapshotted recipient — immune to post-listing changes.
        let royalty = listing.price * listing.royalty_bps / 10_000;
        let existing: i128 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::RoyaltiesPaid)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&SecureDataKey::RoyaltiesPaid, &(existing + royalty));

        env.storage()
            .persistent()
            .remove(&SecureDataKey::Listing(listing_id));

        listing.royalty_recipient
    }

    pub fn royalties_paid(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&SecureDataKey::RoyaltiesPaid)
            .unwrap_or(0)
    }
}
