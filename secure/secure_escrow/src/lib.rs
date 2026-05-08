#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Escrow(Address),
}

#[contract]
pub struct SecureEscrow;

#[contractimpl]
impl SecureEscrow {
    pub fn deposit(env: Env, depositor: Address, amount: i128) {
        depositor.require_auth();
        let key = DataKey::Escrow(depositor.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    pub fn withdraw(env: Env, depositor: Address, amount: i128) {
        depositor.require_auth();
        let key = DataKey::Escrow(depositor.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(balance - amount));
    }

    pub fn balance(env: Env, depositor: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(depositor))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_depositor_can_withdraw_with_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureEscrow);
        let client = SecureEscrowClient::new(&env, &contract_id);

        let depositor = Address::generate(&env);
        env.mock_all_auths();

        client.deposit(&depositor, &1000);
        client.withdraw(&depositor, &500);

        assert_eq!(client.balance(&depositor), 500);
    }

    #[test]
    #[should_panic]
    fn test_withdraw_without_depositor_auth_panics() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureEscrow);
        let client = SecureEscrowClient::new(&env, &contract_id);

        let depositor = Address::generate(&env);
        env.mock_all_auths();
        client.deposit(&depositor, &1000);

        env.clear_auths();
        client.withdraw(&depositor, &500);
    }
}
