//! VULNERABLE: Balance storage key omits the user.
//!
//! A market that stores balances by asset only. Deposits from different users
//! using the same asset overwrite each other, enabling theft or denial of
//! service.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Balance(Symbol),
    UserBalance(Symbol, Address),
}

#[contract]
pub struct BalanceKeyMissingUserContract;

#[contractimpl]
impl BalanceKeyMissingUserContract {
    pub fn deposit(env: Env, user: Address, asset: Symbol, amount: i128) {
        user.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Balance(asset), &amount);
    }

    pub fn balance(env: Env, asset: Symbol) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(asset)).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, testutils::Address as _, Address, Env};

    #[test]
    fn test_vulnerable_deposit_same_asset_overwrites_previous_user() {
        let env = Env::default();
        let contract_id = env.register_contract(None, BalanceKeyMissingUserContract);
        let client = BalanceKeyMissingUserContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let asset = symbol_short!("USDC");

        env.mock_all_auths();
        client.deposit(&alice, &asset, &100);
        assert_eq!(client.balance(&asset), 100);

        client.deposit(&bob, &asset, &200);
        assert_eq!(client.balance(&asset), 200);
    }

    #[test]
    fn test_secure_balance_isolated_by_user() {
        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureBalanceKeyMissingUserContract);
        let client = secure::SecureBalanceKeyMissingUserContractClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        let asset = symbol_short!("USDC");

        env.mock_all_auths();
        client.deposit(&alice, &asset, &100);
        client.deposit(&bob, &asset, &200);

        assert_eq!(client.balance(&alice, &asset), 100);
        assert_eq!(client.balance(&bob, &asset), 200);
    }
}
