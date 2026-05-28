use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureEscrow;

#[contractimpl]
impl SecureEscrow {
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

    /// SECURE: requires both buyer AND seller approval before releasing funds.
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

        // ✅ AND logic — both parties must consent.
        if !(buyer_approved && seller_approved) {
            panic!("release requires both buyer and seller approval");
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
