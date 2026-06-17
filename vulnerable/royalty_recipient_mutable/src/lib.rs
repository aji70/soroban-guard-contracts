//! VULNERABLE: Royalty Recipient Can Be Changed After Sale Starts
//!
//! A marketplace lets sellers update the royalty recipient at any time.
//! Settlement reads the live royalty config rather than the snapshot taken
//! at listing creation. A seller can change the recipient after bids arrive
//! to redirect royalties to an address bidders never agreed to.
//!
//! VULNERABILITY: `settle` reads `RoyaltyRecipient` from live storage
//! instead of the value captured in the listing at creation time.
//!
//! SECURE MIRROR: `secure::SecureMarketplace` snapshots the royalty
//! recipient and rate into the listing struct at creation and reads only
//! that snapshot during settlement.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

#[contracttype]
#[derive(Clone)]
pub struct Listing {
    pub seller: Address,
    pub price: i128,
    pub royalty_bps: i128, // basis points, e.g. 500 = 5 %
}

#[contracttype]
pub enum DataKey {
    /// Live royalty recipient — can be changed at any time.
    RoyaltyRecipient,
    Listing(u64),
    /// Tracks total royalties paid out (for test assertions).
    RoyaltiesPaid,
}

#[contract]
pub struct VulnerableMarketplace;

#[contractimpl]
impl VulnerableMarketplace {
    /// Set or update the royalty recipient. No restriction on timing.
    pub fn set_royalty_recipient(env: Env, seller: Address, recipient: Address) {
        seller.require_auth();
        // ❌ Recipient can be changed after listings are live.
        env.storage()
            .persistent()
            .set(&DataKey::RoyaltyRecipient, &recipient);
    }

    /// Create a listing. Royalty recipient is NOT snapshotted.
    pub fn create_listing(env: Env, seller: Address, listing_id: u64, price: i128, royalty_bps: i128) {
        seller.require_auth();
        if royalty_bps < 0 || royalty_bps > 10_000 {
            panic!("invalid royalty bps");
        }
        env.storage().persistent().set(
            &DataKey::Listing(listing_id),
            &Listing { seller, price, royalty_bps },
        );
    }

    /// VULNERABLE: settle reads the live royalty recipient, not a snapshot.
    ///
    /// # Vulnerability
    /// If the seller calls `set_royalty_recipient` between listing creation
    /// and settlement, royalties flow to the new address.
    pub fn settle(env: Env, buyer: Address, listing_id: u64) -> Address {
        buyer.require_auth();

        let listing: Listing = env
            .storage()
            .persistent()
            .get(&DataKey::Listing(listing_id))
            .expect("listing not found");

        // ❌ Reads live recipient — not the value at listing time.
        let royalty_recipient: Address = env
            .storage()
            .persistent()
            .get(&DataKey::RoyaltyRecipient)
            .expect("royalty recipient not set");

        let royalty = listing.price * listing.royalty_bps / 10_000;
        let existing: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RoyaltiesPaid)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::RoyaltiesPaid, &(existing + royalty));

        env.storage()
            .persistent()
            .remove(&DataKey::Listing(listing_id));

        royalty_recipient
    }

    pub fn royalties_paid(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RoyaltiesPaid)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableMarketplaceClient<'static>, Address, Address, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let original_recipient = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();
        client.set_royalty_recipient(&seller, &original_recipient);
        client.create_listing(&seller, &1, &10_000, &500); // 5% royalty
        (env, client, seller, original_recipient, buyer)
    }

    /// Vulnerable path: seller changes recipient after listing; settlement uses new address.
    #[test]
    fn test_vulnerable_royalty_redirected_after_listing() {
        let (env, client, seller, original_recipient, buyer) = setup();
        let attacker_wallet = Address::generate(&env);

        // Seller redirects royalties after the listing is live.
        client.set_royalty_recipient(&seller, &attacker_wallet);

        let paid_to = client.settle(&buyer, &1);
        assert_eq!(
            paid_to, attacker_wallet,
            "vulnerable: royalties go to new recipient"
        );
        assert_ne!(paid_to, original_recipient);
    }

    /// Boundary: if recipient is unchanged, settlement is correct in both versions.
    #[test]
    fn test_unchanged_recipient_settles_correctly() {
        let (env, client, _seller, original_recipient, buyer) = setup();

        let paid_to = client.settle(&buyer, &1);
        assert_eq!(paid_to, original_recipient);
    }

    /// Secure path: settlement must use the recipient snapshotted at listing creation.
    #[test]
    fn test_secure_settlement_uses_snapshot_recipient() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let original_recipient = Address::generate(&env);
        let attacker_wallet = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();

        client.set_royalty_recipient(&seller, &original_recipient);
        client.create_listing(&seller, &1, &10_000, &500);

        // Seller tries to redirect royalties after listing.
        client.set_royalty_recipient(&seller, &attacker_wallet);

        let paid_to = client.settle(&buyer, &1);
        assert_eq!(
            paid_to, original_recipient,
            "secure: snapshot recipient must be used"
        );
        assert_ne!(paid_to, attacker_wallet);
    }

    /// Secure path: royalty amount is also taken from the snapshot.
    #[test]
    fn test_secure_royalty_amount_from_snapshot() {
        use crate::secure::SecureMarketplaceClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = SecureMarketplaceClient::new(&env, &id);
        let seller = Address::generate(&env);
        let recipient = Address::generate(&env);
        let buyer = Address::generate(&env);
        env.mock_all_auths();

        client.set_royalty_recipient(&seller, &recipient);
        client.create_listing(&seller, &1, &10_000, &500); // 5% of 10_000 = 500

        client.settle(&buyer, &1);
        assert_eq!(client.royalties_paid(), 500);
    }
}
