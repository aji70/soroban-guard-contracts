//! VULNERABLE: Deposit Cap Is Checked Before Fee-on-Transfer Delta
//!
//! The cap check uses the user-supplied `amount` before transfer while internal
//! accounting credits the post-transfer balance delta.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const DEPOSIT_CAP: i128 = 100;

#[contracttype]
pub enum DataKey {
    TotalCredited,
    Token,
}

pub mod token {
    use soroban_sdk::{contractclient, Address, Env};

    #[contractclient(name = "TokenClient")]
    pub trait Token {
        fn transfer(env: Env, from: Address, to: Address, amount: i128);
        fn balance(env: Env, id: Address) -> i128;
    }
}

#[contract]
pub struct DepositCapWrongAmount;

#[contractimpl]
impl DepositCapWrongAmount {
    pub fn initialize(env: Env, token: Address) {
        env.storage().persistent().set(&DataKey::Token, &token);
    }

    /// VULNERABLE: cap check uses `amount` before transfer; credits actual delta after.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");

        let total: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalCredited)
            .unwrap_or(0);

        // ❌ Cap check uses the requested amount only, not cumulative credited totals.
        assert!(amount <= DEPOSIT_CAP, "deposit cap exceeded");

        let token: Address = env.storage().persistent().get(&DataKey::Token).unwrap();
        let token_client = token::TokenClient::new(&env, &token);
        let vault = env.current_contract_address();
        let pre = token_client.balance(&vault);

        token_client.transfer(&user, &vault, &amount);

        let post = token_client.balance(&vault);
        let received = post - pre;

        env.storage()
            .persistent()
            .set(&DataKey::TotalCredited, &(total + received));
    }

    pub fn total_credited(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalCredited)
            .unwrap_or(0)
    }
}

#[contracttype]
pub enum TokenKey {
    Balance(Address),
}

#[contract]
pub struct FeeToken;

#[contractimpl]
impl FeeToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = TokenKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// 10% transfer fee — recipient receives 90% of `amount`.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let received = amount * 90 / 100;
        let from_key = TokenKey::Balance(from.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");
        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));

        let to_key = TokenKey::Balance(to.clone());
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&to_key, &(to_bal + received));
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&TokenKey::Balance(id))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secure::SecureDepositCapClient;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup_vulnerable(env: &Env) -> (Address, DepositCapWrongAmountClient<'_>) {
        let token = env.register_contract(None, FeeToken);
        let vault = env.register_contract(None, DepositCapWrongAmount);
        let vault_client = DepositCapWrongAmountClient::new(env, &vault);
        vault_client.initialize(&token);
        (token, vault_client)
    }

    fn setup_secure(env: &Env) -> (Address, SecureDepositCapClient<'_>) {
        let token = env.register_contract(None, FeeToken);
        let vault = env.register_contract(None, secure::SecureDepositCap);
        let vault_client = SecureDepositCapClient::new(env, &vault);
        vault_client.initialize(&token);
        (token, vault_client)
    }

    fn mint_to(env: &Env, token: &Address, user: &Address, amount: i128) {
        FeeTokenClient::new(env, token).mint(user, &amount);
    }

    /// Cap check passes on requested amounts but credited totals can exceed the cap.
    #[test]
    fn test_vulnerable_exceeds_cap_via_fee_on_transfer() {
        let env = Env::default();
        env.mock_all_auths();

        let (token, client) = setup_vulnerable(&env);
        let user = Address::generate(&env);
        mint_to(&env, &token, &user, 200);

        client.deposit(&user, &DEPOSIT_CAP);
        assert_eq!(client.total_credited(), 90);

        client.deposit(&user, &DEPOSIT_CAP);
        assert_eq!(client.total_credited(), 180);
        assert!(
            client.total_credited() > DEPOSIT_CAP,
            "credited total exceeds cap"
        );
    }

    /// Boundary: deposit exactly at the cap twice; credited total exceeds the cap.
    #[test]
    fn test_vulnerable_boundary_deposit_at_cap_exceeds_credited_total() {
        let env = Env::default();
        env.mock_all_auths();

        let (token, client) = setup_vulnerable(&env);
        let user = Address::generate(&env);
        mint_to(&env, &token, &user, 200);

        client.deposit(&user, &DEPOSIT_CAP);
        assert_eq!(client.total_credited(), 90);

        client.deposit(&user, &DEPOSIT_CAP);
        assert!(
            client.total_credited() > DEPOSIT_CAP,
            "credited total exceeds cap after boundary deposit"
        );
    }

    /// Secure path measures post-transfer delta and rejects cap violations.
    #[test]
    #[should_panic(expected = "deposit cap exceeded")]
    fn test_secure_rejects_deposit_over_cap() {
        let env = Env::default();
        env.mock_all_auths();

        let (token, client) = setup_secure(&env);
        let user = Address::generate(&env);
        mint_to(&env, &token, &user, 200);

        client.deposit(&user, &DEPOSIT_CAP);
        client.deposit(&user, &DEPOSIT_CAP);
    }
}
