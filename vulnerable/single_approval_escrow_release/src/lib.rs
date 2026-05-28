//! VULNERABLE: Escrow Release Requires Only One Party Approval
//!
//! A two-party escrow is designed to release funds only after both the
//! buyer and the seller have approved. However, the `release` function
//! uses OR logic: if either party has approved, funds are released
//! immediately. Either party can unilaterally drain the escrow.
//!
//! VULNERABILITY: release guard is `buyer_approved || seller_approved`
//! instead of `buyer_approved && seller_approved`.
//!
//! SECURE MIRROR: `secure::SecureEscrow` requires both approvals before
//! releasing funds.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Buyer,
    Seller,
    Balance,
    BuyerApproved,
    SellerApproved,
}

#[contract]
pub struct VulnerableEscrow;

#[contractimpl]
impl VulnerableEscrow {
    /// Initialise the escrow with buyer and seller addresses.
    pub fn initialize(env: Env, buyer: Address, seller: Address) {
        if env.storage().persistent().has(&DataKey::Buyer) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Buyer, &buyer);
        env.storage().persistent().set(&DataKey::Seller, &seller);
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &0_i128);
        env.storage()
            .persistent()
            .set(&DataKey::BuyerApproved, &false);
        env.storage()
            .persistent()
            .set(&DataKey::SellerApproved, &false);
    }

    /// Deposit funds into the escrow. Only the buyer may deposit.
    pub fn deposit(env: Env, amount: i128) {
        let buyer: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Buyer)
            .expect("not initialized");
        buyer.require_auth();

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &(balance + amount));
    }

    /// Record approval from the calling party (buyer or seller).
    pub fn approve(env: Env, party: Address) {
        party.require_auth();

        let buyer: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Buyer)
            .expect("not initialized");
        let seller: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Seller)
            .expect("not initialized");

        if party == buyer {
            env.storage()
                .persistent()
                .set(&DataKey::BuyerApproved, &true);
        } else if party == seller {
            env.storage()
                .persistent()
                .set(&DataKey::SellerApproved, &true);
        } else {
            panic!("caller is not a party to this escrow");
        }
    }

    /// VULNERABLE: releases funds if either party has approved (OR logic).
    ///
    /// # Vulnerability
    /// Uses `buyer_approved || seller_approved` instead of `&&`.
    /// Impact: either party can unilaterally release funds without the other's consent.
    pub fn release(env: Env) -> i128 {
        let buyer_approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::BuyerApproved)
            .unwrap_or(false);
        let seller_approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::SellerApproved)
            .unwrap_or(false);

        // ❌ OR logic — one approval is sufficient.
        if !(buyer_approved || seller_approved) {
            panic!("release requires at least one approval");
        }

        let balance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Balance, &0_i128);
        balance
    }

    pub fn get_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance)
            .unwrap_or(0)
    }

    pub fn is_buyer_approved(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::BuyerApproved)
            .unwrap_or(false)
    }

    pub fn is_seller_approved(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::SellerApproved)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableEscrowClient<'static>, Address, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableEscrow);
        let client = VulnerableEscrowClient::new(&env, &id);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&buyer, &seller);
        client.deposit(&1000);
        (env, client, buyer, seller)
    }

    /// Vulnerable path: seller alone approves and release succeeds.
    #[test]
    fn test_vulnerable_seller_only_approval_releases_funds() {
        let (_env, client, _buyer, seller) = setup();

        // Only seller approves — buyer has not consented.
        client.approve(&seller);
        assert!(client.is_seller_approved());
        assert!(!client.is_buyer_approved());

        let released = client.release();
        assert_eq!(released, 1000);
        assert_eq!(client.get_balance(), 0);
    }

    /// Boundary: no approvals must block release in both versions.
    #[test]
    fn test_no_approval_blocks_release() {
        let (_env, client, _buyer, _seller) = setup();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.release();
        }));
        assert!(result.is_err(), "release without any approval must panic");
        assert_eq!(client.get_balance(), 1000, "funds must remain locked");
    }

    /// Secure path: seller-only approval must not release funds.
    #[test]
    fn test_secure_rejects_single_party_release() {
        use crate::secure::SecureEscrowClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureEscrow);
        let client = SecureEscrowClient::new(&env, &id);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&buyer, &seller);
        client.deposit(&1000);

        // Only seller approves.
        client.approve(&seller);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.release();
        }));
        assert!(
            result.is_err(),
            "secure release must require both approvals"
        );
        assert_eq!(client.get_balance(), 1000, "funds must remain locked");
    }

    /// Secure path: both approvals allow release.
    #[test]
    fn test_secure_releases_with_both_approvals() {
        use crate::secure::SecureEscrowClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureEscrow);
        let client = SecureEscrowClient::new(&env, &id);
        let buyer = Address::generate(&env);
        let seller = Address::generate(&env);
        env.mock_all_auths();

        client.initialize(&buyer, &seller);
        client.deposit(&1000);

        client.approve(&buyer);
        client.approve(&seller);

        let released = client.release();
        assert_eq!(released, 1000);
        assert_eq!(client.get_balance(), 0);
    }
}
