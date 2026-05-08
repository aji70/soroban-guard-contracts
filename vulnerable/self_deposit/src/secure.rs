use super::{get_allowance, get_balance, set_allowance, set_balance};
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }

    pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        if to == env.current_contract_address() {
            panic!("cannot transfer to contract itself");
        }

        from.require_auth();
        let from_balance = get_balance(&env, &from);
        let to_balance = get_balance(&env, &to);
        set_balance(&env, &from, from_balance - amount);
        set_balance(&env, &to, to_balance + amount);
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        if to == env.current_contract_address() {
            panic!("cannot transfer to contract itself");
        }

        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");

        let from_balance = get_balance(&env, &from);
        assert!(from_balance >= amount, "insufficient balance");

        set_allowance(&env, &from, &spender, allowance - amount);
        set_balance(&env, &from, from_balance - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
    }
}
