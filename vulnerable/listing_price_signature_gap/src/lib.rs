//! VULNERABLE: Listing Price Signature Gap
//!
//! An NFT marketplace accepts an off-chain seller signature that covers only
//! `(nft_id, seller)`. Because the price, payment token, expiry, and domain
//! separator are absent from the signed payload, a buyer can submit the
//! seller's valid signature alongside any price they choose — including zero.
//!
//! VULNERABILITY: `fill_listing` hashes only `(nft_id, seller_bytes)`.
//! Any caller who obtains a valid signature can substitute an arbitrary price.
//!
//! SECURE MIRROR: `secure::SecureListingMarketplace` binds the signature to
//! `(contract_id, nft_id, seller, price, expiry_ledger)`.

#![no_std]
use soroban_sdk::{
    contract, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env,
};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    Owner(u64),
    Balance(Address),
    /// Tracks how many fills occurred for a given nft_id (test assertions).
    FillCount(u64),
}

// ---------------------------------------------------------------------------
// Digest helpers (exposed for test assertions)
// ---------------------------------------------------------------------------

/// ❌ BUG: digest covers only nft_id and seller — price is absent.
pub fn vulnerable_listing_digest(env: &Env, nft_id: u64, seller: &Address) -> BytesN<32> {
    let mut msg = Bytes::new(env);
    msg.append(&Bytes::from_array(env, &nft_id.to_be_bytes()));
    msg.append(&seller.clone().to_xdr(env));
    env.crypto().sha256(&msg).into()
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableListingMarketplace;

#[contractimpl]
impl VulnerableListingMarketplace {
    pub fn mint(env: Env, owner: Address, nft_id: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::Owner(nft_id), &owner);
    }

    pub fn fund(env: Env, buyer: Address, amount: i128) {
        let bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(buyer.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(buyer), &(bal + amount));
    }

    /// VULNERABLE: `price` is caller-supplied and not covered by the signature.
    ///
    /// # Vulnerability
    /// The seller signs `hash(nft_id || seller_bytes)`. A buyer can reuse that
    /// signature with any `price`, including 1. Impact: seller receives far
    /// less than intended.
    pub fn fill_listing(
        env: Env,
        buyer: Address,
        seller: Address,
        nft_id: u64,
        price: i128,
        _sig: BytesN<64>,
    ) {
        buyer.require_auth();

        // Simulate: off-chain verifier checked _sig over vulnerable_listing_digest.
        // The digest does NOT include `price`, so any price is accepted.
        let _digest = vulnerable_listing_digest(&env, nft_id, &seller);

        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(nft_id))
            .expect("token not found");
        if owner != seller {
            panic!("seller mismatch");
        }

        // Deduct payment from buyer.
        let buyer_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(buyer.clone()))
            .unwrap_or(0);
        if buyer_bal < price {
            panic!("insufficient funds");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Balance(buyer.clone()), &(buyer_bal - price));

        // Credit seller.
        let seller_bal: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(seller.clone()))
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance(seller.clone()), &(seller_bal + price));

        // Transfer NFT.
        env.storage()
            .persistent()
            .set(&DataKey::Owner(nft_id), &buyer);

        let key = DataKey::FillCount(nft_id);
        let count: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(count + 1));
    }

    pub fn owner_of(env: Env, nft_id: u64) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Owner(nft_id))
    }

    pub fn balance_of(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    /// Expose the digest so tests can assert price is absent.
    pub fn listing_digest(env: Env, nft_id: u64, seller: Address) -> BytesN<32> {
        vulnerable_listing_digest(&env, nft_id, &seller)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

    /// Demonstrates the vulnerability: buyer fills at price=1 using a
    /// signature the seller intended for a much higher price.
    #[test]
    fn test_vulnerable_buyer_fills_at_arbitrary_low_price() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableListingMarketplace);
        let client = VulnerableListingMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let nft_id: u64 = 1;

        client.mint(&seller, &nft_id);
        client.fund(&buyer, &1000);

        // Seller "signed" a listing for nft_id — price is NOT in the payload.
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        // ❌ Buyer submits price=1 instead of the intended 1000.
        client.fill_listing(&buyer, &seller, &nft_id, &1, &dummy_sig);

        // NFT transferred; seller received only 1 unit.
        assert_eq!(client.owner_of(&nft_id), Some(buyer.clone()));
        assert_eq!(client.balance_of(&seller), 1);
        assert_eq!(client.balance_of(&buyer), 999); // kept 999
    }

    /// Boundary: digest is identical regardless of price (price not bound).
    #[test]
    fn test_vulnerable_digest_independent_of_price() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableListingMarketplace);
        let client = VulnerableListingMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let nft_id: u64 = 2;

        // The digest is the same regardless of what price the buyer will supply.
        let digest_a = client.listing_digest(&nft_id, &seller);
        let digest_b = client.listing_digest(&nft_id, &seller);
        assert_eq!(digest_a, digest_b);
    }

    /// Secure version: fill with a price different from the signed price is rejected.
    #[test]
    #[should_panic(expected = "price mismatch")]
    fn test_secure_rejects_altered_price() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureListingMarketplace);
        let client = secure::SecureListingMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let nft_id: u64 = 3;
        let intended_price: i128 = 1000;

        client.mint(&seller, &nft_id);
        client.fund(&buyer, &1000);

        // Build a valid signature over the full payload at intended_price.
        let sig = secure::make_test_sig(&env, &id, nft_id, &seller, intended_price, u32::MAX);

        // ✅ Buyer tries to fill at price=1 — must panic.
        client.fill_listing(&buyer, &seller, &nft_id, &1, &sig, &u32::MAX);
    }

    /// Secure version: fill at the correct signed price succeeds.
    #[test]
    fn test_secure_fill_at_correct_price_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureListingMarketplace);
        let client = secure::SecureListingMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let nft_id: u64 = 4;
        let price: i128 = 500;

        client.mint(&seller, &nft_id);
        client.fund(&buyer, &500);

        let sig = secure::make_test_sig(&env, &id, nft_id, &seller, price, u32::MAX);
        client.fill_listing(&buyer, &seller, &nft_id, &price, &sig, &u32::MAX);

        assert_eq!(client.owner_of(&nft_id), Some(buyer));
        assert_eq!(client.balance_of(&seller), 500);
    }
}
