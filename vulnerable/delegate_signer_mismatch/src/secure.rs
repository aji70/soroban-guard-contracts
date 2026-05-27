//! SECURE: Delegate Signer Correctly Enforced
//!
//! Identical token but `transfer_from` calls `delegate.require_auth()` to
//! bind the signer to the allowance being consumed.

use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{get_allowance, get_balance, set_allowance, set_balance};

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current + amount);
    }

    pub fn approve(env: Env, owner: Address, delegate: Address, amount: i128) {
        owner.require_auth();
        set_allowance(&env, &owner, &delegate, amount);
    }

    /// Delegated transfer — delegate spends owner's allowance.
    ///
    /// ✅ Authorizes `delegate` — only the delegate with the allowance can spend it.
    pub fn transfer_from(
        env: Env,
        delegate: Address,
        owner: Address,
        to: Address,
        amount: i128,
    ) -> i128 {
        // ✅ Correct signer — delegate must authorize.
        delegate.require_auth();

        let allowance = get_allowance(&env, &owner, &delegate);
        assert!(allowance >= amount, "insufficient allowance");

        let owner_bal = get_balance(&env, &owner);
        assert!(owner_bal >= amount, "insufficient balance");

        set_balance(&env, &owner, owner_bal - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);
        set_allowance(&env, &owner, &delegate, allowance - amount);

        allowance - amount
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, delegate: Address) -> i128 {
        get_allowance(&env, &owner, &delegate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        SecureTokenClient<'static>,
        Address,
        Address,
        Address,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &id);
        let owner = Address::generate(&env);
        let legitimate_delegate = Address::generate(&env);
        let attacker_delegate = Address::generate(&env);
        let recipient = Address::generate(&env);

        client.mint(&owner, &1000);
        client.approve(&owner, &legitimate_delegate, &300);
        client.approve(&owner, &attacker_delegate, &50);

        (
            env,
            client,
            owner,
            legitimate_delegate,
            attacker_delegate,
            recipient,
        )
    }

    /// Legitimate delegate can use their own allowance — secure version succeeds.
    #[test]
    fn test_secure_legitimate_delegate_can_spend() {
        let (_env, client, owner, legitimate_delegate, _attacker_delegate, recipient) = setup();

        client.transfer_from(&legitimate_delegate, &owner, &recipient, &100);

        assert_eq!(client.allowance(&owner, &legitimate_delegate), 200);
        assert_eq!(client.balance(&recipient), 100);
    }

    /// Attacker cannot consume another delegate's allowance — secure version panics.
    #[test]
    #[should_panic]
    fn test_secure_attacker_delegate_rejected() {
        let (env, client, owner, legitimate_delegate, _attacker_delegate, recipient) = setup();

        // Don't mock auth for this call — legitimate_delegate must sign but won't.
        env.mock_auths(&[]);

        // Attacker tries to use legitimate_delegate's allowance — must panic.
        client.transfer_from(&legitimate_delegate, &owner, &recipient, &200);
    }
}
