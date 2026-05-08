//! VULNERABLE: Unprotected Burn Function
//!
//! A token contract where `burn()` destroys tokens from any account without
//! requiring authorization from that account. Any caller can burn any account's
//! tokens, deflating supply and wiping balances.
//!
//! VULNERABILITY: Missing `account.require_auth()` before burning tokens.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct UnprotectedBurnToken;

#[contractimpl]
impl UnprotectedBurnToken {
    /// Mint `amount` tokens to `to`. Emits a `mint` event.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &(current.checked_add(amount).expect("mint overflow")));
        env.events()
            .publish((symbol_short!("mint"),), (to, amount));
    }

    /// VULNERABLE: Burns `amount` tokens from `account` without verifying
    /// that the caller is `account`. No `account.require_auth()` call.
    pub fn burn(env: Env, account: Address, amount: i128) {
        // ❌ Missing: account.require_auth();

        let key = DataKey::Balance(account.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);

        // No auth check — anyone can call this and burn tokens from any account
        env.storage()
            .persistent()
            .set(&key, &(balance.checked_sub(amount).expect("burn underflow")));

        env.events()
            .publish((symbol_short!("burn"),), (account, amount));
    }

    /// Returns the balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, UnprotectedBurnToken);
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        (env, contract_id, owner, attacker)
    }

    #[test]
    fn test_owner_burns_own_tokens_normally() {
        let (env, contract_id, owner, _attacker) = setup();
        let client = UnprotectedBurnTokenClient::new(&env, &contract_id);

        // Owner mints tokens to themselves
        client.mint(&owner, &1000);
        assert_eq!(client.balance(&owner), 1000);

        // Owner burns their own tokens
        client.burn(&owner, &300);
        assert_eq!(client.balance(&owner), 700);
    }

    #[test]
    fn test_attacker_burns_another_account_tokens_without_auth() {
        let (env, contract_id, owner, _attacker) = setup();
        let client = UnprotectedBurnTokenClient::new(&env, &contract_id);

        // Owner mints tokens to themselves
        client.mint(&owner, &1000);
        assert_eq!(client.balance(&owner), 1000);

        // ❌ VULNERABILITY: Attacker can burn owner's tokens without authorization
        client.burn(&owner, &500);
        assert_eq!(client.balance(&owner), 500);

        // Attacker can burn all remaining tokens
        client.burn(&owner, &500);
        assert_eq!(client.balance(&owner), 0);
    }
}
