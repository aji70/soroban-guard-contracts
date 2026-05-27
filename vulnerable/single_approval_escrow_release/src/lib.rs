//! VULNERABLE: Escrow Release Requires Only One Party Approval
//!
//! A two-party escrow releases funds after buyer and seller approval, but
//! the release guard uses OR logic. Either party can unilaterally release.
//!
//! VULNERABILITY: `buyer_approved || seller_approved` instead of `&&`.
//!
//! SECURE MIRROR: `secure::SecureEscrow` requires both approvals.

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
    pub fn initialize(env: Env, buyer: Address, seller: Address) {
        if env.storage().persistent().has(&DataKey::Buyer) { panic!("already initialized"); }
        env.storage().persistent().set(&DataKey::Buyer, &buyer);
        env.storage().persistent().set(&DataKey::Seller, &seller);
        env.storage().persistent().set(&DataKey::Balance, &0_i128);
        env.storage().persistent().set(&DataKey::BuyerApproved, &false);
        env.storage().persistent().set(&DataKey::SellerApproved, &false);
    }

    pub fn deposit(env: Env, amount: i128) {
        let buyer: Address = env.storage().persistent().get(&DataKey::Buyer).expect("not initialized");
        buyer.require_auth();
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance, &(balance + amount));
    }

    pub fn approve(env: Env, party: Address) {
        party.require_auth();
        let buyer: Address = env.storage().persistent().get(&DataKey::Buyer).expect("not initialized");
        let seller: Address = env.storage().persistent().get(&DataKey::Seller).expect("not initialized");
        if party == buyer {
            env.storage().persistent().set(&DataKey::BuyerApproved, &true);
        } else if party == seller {
            env.storage().persistent().set(&DataKey::SellerApproved, &true);
        } else {
            panic!("caller is not a party");
        }
    }

    /// VULNERABLE: OR logic — one approval is sufficient.
    pub fn release(env: Env) -> i128 {
        let buyer_approved: bool = env.storage().persistent().get(&DataKey::BuyerApproved).unwrap_or(false);
        let seller_approved: bool = env.storage().persistent().get(&DataKey::SellerApproved).unwrap_or(false);
        // ❌ OR logic
        if !(buyer_approved || seller_approved) { panic!("no approval"); }
        let balance: i128 = env.storage().persistent().get(&DataKey::Balance).unwrap_or(0);
        env.storage().persistent().set(&DataKey::Balance, &0_i128);
        balance
    }

    pub fn get_balance(env: Env) -> i128 { env.storage().persistent().get(&DataKey::Balance).unwrap_or(0) }
    pub fn is_buyer_approved(env: Env) -> bool { env.storage().persistent().get(&DataKey::BuyerApproved).unwrap_or(false) }
    pub fn is_seller_approved(env: Env) -> bool { env.storage().persistent().get(&DataKey::SellerApproved).unwrap_or(false) }
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

    #[test]
    fn test_vulnerable_seller_only_approval_releases_funds() {
        let (_env, client, _buyer, seller) = setup();
        client.approve(&seller);
        let released = client.release();
        assert_eq!(released, 1000);
        assert_eq!(client.get_balance(), 0);
    }

    #[test]
    fn test_no_approval_blocks_release() {
        let (_env, client, _buyer, _seller) = setup();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { client.release(); }));
        assert!(result.is_err());
        assert_eq!(client.get_balance(), 1000);
    }

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
        client.approve(&seller);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| { client.release(); }));
        assert!(result.is_err());
        assert_eq!(client.get_balance(), 1000);
    }

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
