use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureContract;

#[contractimpl]
impl SecureContract {
    // SECURE: The authorized token is stored in instance storage during initialization.
    // The withdraw function uses this stored token rather than accepting one from the caller.
    pub fn init(env: Env, token: Address) {
        env.storage().instance().set(&symbol_short!("token"), &token);
    }

    pub fn withdraw(env: Env, caller: Address, amount: i128) {
        caller.require_auth();
        
        let authorized_token: Address = env.storage().instance().get(&symbol_short!("token")).unwrap();
        
        let token_client = soroban_sdk::token::Client::new(&env, &authorized_token);
        token_client.transfer(&env.current_contract_address(), &caller, &amount);
    }
}
