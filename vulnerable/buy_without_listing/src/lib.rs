//! VULNERABLE: NFT Marketplace Buy Without Active Listing
//!
//! The marketplace `buy` function accepts seller and price as caller-supplied
//! arguments and transfers the NFT immediately, without verifying that the
//! seller ever created a listing. Any NFT owner can have their token taken
//! by an attacker who simply supplies the owner's address and any price.
//!
//! VULNERABILITY: `buy` constructs listing terms entirely from caller
//! arguments. No stored listing is consulted, so the seller's intent is
//! never verified.
//!
//! SECURE MIRROR: `secure::SecureMarketplace` requires a stored listing keyed
//! by `(nft_contract, token_id)` before executing any transfer.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone)]
pub struct Listing {
    pub seller: Address,
    pub price: i128,
}

#[contracttype]
pub enum DataKey {
    /// NFT ownership: token_id -> owner
    Owner(u64),
    /// Buyer balances (simulated payment token)
    Balance(Address),
    /// Active listing: token_id -> Listing
    Listing(u64),
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableMarketplace;

#[contractimpl]
impl VulnerableMarketplace {
    /// Mint an NFT to `owner` (test helper).
    pub fn mint(env: Env, owner: Address, token_id: u64) {
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &owner);
    }

    /// Credit `buyer` with `amount` of the payment token (test helper).
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

    /// VULNERABLE: transfers the NFT using caller-supplied `seller` and `price`
    /// without checking for a stored listing.
    ///
    /// # Vulnerability
    /// Any caller can drain any NFT from any owner by supplying the owner's
    /// address as `seller`. No listing is required. Impact: owners lose NFTs
    /// they never listed.
    pub fn buy(env: Env, buyer: Address, token_id: u64, seller: Address, price: i128) {
        buyer.require_auth();

        // ❌ BUG: no listing lookup — terms are taken from caller arguments.
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(token_id))
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
            .set(&DataKey::Owner(token_id), &buyer);
    }

    pub fn owner_of(env: Env, token_id: u64) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Owner(token_id))
    }

    pub fn balance_of(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
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
    use soroban_sdk::{testutils::Address as _, Address, Env};

    /// Demonstrates the vulnerability: attacker buys an unlisted NFT.
    #[test]
    fn test_vulnerable_buy_unlisted_nft_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let attacker = Address::generate(&env);
        let token_id: u64 = 1;

        // Seller owns the NFT but has never created a listing.
        client.mint(&seller, &token_id);
        client.fund(&attacker, &1); // pay 1 unit — far below any fair price

        // ❌ Attacker buys the NFT without a listing existing.
        client.buy(&attacker, &token_id, &seller, &1);

        // NFT has been transferred to the attacker.
        assert_eq!(client.owner_of(&token_id), Some(attacker));
    }

    /// Boundary: buy with wrong seller address panics.
    #[test]
    #[should_panic(expected = "seller mismatch")]
    fn test_vulnerable_wrong_seller_panics() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableMarketplace);
        let client = VulnerableMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let wrong_seller = Address::generate(&env);
        let attacker = Address::generate(&env);
        let token_id: u64 = 2;

        client.mint(&seller, &token_id);
        client.fund(&attacker, &100);

        client.buy(&attacker, &token_id, &wrong_seller, &100);
    }

    /// Secure version: buy without a listing is rejected.
    #[test]
    #[should_panic(expected = "no active listing")]
    fn test_secure_buy_without_listing_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = secure::SecureMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let attacker = Address::generate(&env);
        let token_id: u64 = 3;

        client.mint(&seller, &token_id);
        client.fund(&attacker, &1000);

        // ✅ Must panic — no listing was created.
        client.buy(&attacker, &token_id, &1);
    }

    /// Secure version: buy succeeds when a valid listing exists.
    #[test]
    fn test_secure_buy_with_listing_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureMarketplace);
        let client = secure::SecureMarketplaceClient::new(&env, &id);

        let seller = Address::generate(&env);
        let buyer = Address::generate(&env);
        let token_id: u64 = 4;

        client.mint(&seller, &token_id);
        client.fund(&buyer, &500);
        client.list(&seller, &token_id, &500);

        client.buy(&buyer, &token_id, &500);

        assert_eq!(client.owner_of(&token_id), Some(buyer));
    }
}
