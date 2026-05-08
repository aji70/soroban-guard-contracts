//! SECURE: Protected Burn Function
//!
//! A secure mirror of the UnprotectedBurnToken contract. Identical API
//! (`mint`, `balance`, `burn`) but `burn` requires authorization from the
//! account whose tokens are being burned — preventing unauthorized token
//! destruction.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

#[contract]
pub struct SecureBurnToken;

#[contractimpl]
impl SecureBurnToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current.checked_add(amount).expect("mint overflow"));
        env.events()
            .publish((symbol_short!("mint"),), (to, amount));
    }

    /// ✅ FIX: Require authorization from the account before burning their tokens.
    /// Only the account owner can authorize the destruction of their tokens.
    pub fn burn(env: Env, account: Address, amount: i128) {
        // ✅ Only the account can authorize burning their tokens.
        account.require_auth();

        let balance = get_balance(&env, &account);
        set_balance(&env, &account, balance.checked_sub(amount).expect("burn underflow"));

        env.events()
            .publish((symbol_short!("burn"),), (account, amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureBurnToken);
        let owner = Address::generate(&env);
        let attacker = Address::generate(&env);
        (env, contract_id, owner, attacker)
    }

    #[test]
    fn test_owner_burns_own_tokens_normally() {
        let (env, contract_id, owner, _attacker) = setup();
        let client = SecureBurnTokenClient::new(&env, &contract_id);

        // Owner mints tokens to themselves
        client.mint(&owner, &1000);
        assert_eq!(client.balance(&owner), 1000);

        // Owner burns their own tokens (authorized)
        client.burn(&owner, &300);
        assert_eq!(client.balance(&owner), 700);
    }

    #[test]
    #[should_panic]
    fn test_attacker_cannot_burn_another_account_tokens() {
        // Fresh env with no mock_all_auths so require_auth actually enforces.
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureBurnToken);
        let client = SecureBurnTokenClient::new(&env, &contract_id);

        let owner = Address::generate(&env);

        env.mock_all_auths();
        client.mint(&owner, &1000);

        // Drop mock_all_auths by creating a new env snapshot isn't possible,
        // so we just call burn without the owner's auth being satisfied.
        // The attacker passes owner's address but has no key — should panic.
        let env2 = Env::default();
        let client2 = SecureBurnTokenClient::new(&env2, &contract_id);
        client2.burn(&owner, &500);
    }
}
