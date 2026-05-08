//! VULNERABLE: Missing Persistent Storage TTL Renewal
//!
//! Soroban persistent storage entries expire after their ledger TTL window.
//! This token stores balances in persistent storage but never calls
//! `env.storage().persistent().extend_ttl(...)`, so inactive balances
//! eventually disappear.
//!
//! VULNERABILITY: after roughly the network's `max_entry_expiration` / max TTL
//! window, balance entries expire and `balance()` falls back to `0`, making
//! funds or data permanently inaccessible.
//!
//! Severity: Low (liveness, not direct fund theft)

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

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
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    /// Mint `amount` tokens to `to`. No auth check — unprotected by design for test setup.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        let new_balance = current.checked_add(amount).expect("mint: balance overflow");
        // ❌ No persistent().extend_ttl(...) after the write.
        set_balance(&env, &to, new_balance);
    }

    /// Returns the balance of `account`. Defaults to 0 if the entry has expired or never existed.
    ///
    /// # Vulnerability
    /// Missing `extend_ttl` — reading an expired entry returns 0, silently hiding lost funds.
    pub fn balance(env: Env, account: Address) -> i128 {
        // ❌ No persistent().extend_ttl(...) after the read.
        get_balance(&env, &account)
    }

    /// VULNERABLE: transfers `amount` from `from` to `to` without renewing either balance entry's TTL.
    /// After the network's max TTL window, both entries expire and balances read as 0.
    ///
    /// # Vulnerability
    /// Missing `extend_ttl` on both storage writes. Impact: funds become permanently inaccessible.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        let new_from = from_balance
            .checked_sub(amount)
            .expect("transfer: insufficient balance");
        let new_to = to_balance
            .checked_add(amount)
            .expect("transfer: recipient balance overflow");

        // ❌ No extend_ttl — entries expire and balances are lost.
        env.storage().persistent().set(&from_key, &new_from);
        env.storage().persistent().set(&to_key, &new_to);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{storage::Persistent as _, Address as _, Ledger as _},
        Address, Env,
    };

    fn pin_contract_instance(env: &Env, contract_id: &Address) {
        env.as_contract(contract_id, || {
            let max_ttl = env.storage().max_ttl();
            env.storage().instance().extend_ttl(max_ttl, max_ttl);
        });
    }

    #[test]
    fn test_transfer_works_normally() {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.mint(&bob, &100);
        client.transfer(&alice, &bob, &200);

        assert_eq!(client.balance(&alice), 300);
        assert_eq!(client.balance(&bob), 300);
    }

    #[test]
    #[should_panic]
    fn test_balance_entry_expires_without_extend_ttl() {
        let env = Env::default();
        env.ledger().set_min_persistent_entry_ttl(5);
        env.ledger().set_max_entry_ttl(20);

        let contract_id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        client.mint(&alice, &500);

        // Keep the contract instance alive so this test isolates the balance
        // entry expiry. The vulnerability is that the persistent balance slot
        // itself is never renewed.
        pin_contract_instance(&env, &contract_id);

        env.as_contract(&contract_id, || {
            assert_eq!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Balance(alice.clone())),
                4
            );
        });

        env.ledger().set_sequence_number(6);

        // After the entry TTL window passes, the balance record is archived.
        // In this test harness, touching that archived key panics. On a real
        // network the contract call would not execute at all once the entry has
        // expired. Either way, after roughly `max_entry_expiration` / max-TTL
        // ledgers, the user's funds become inaccessible if the contract never
        // renews the persistent entry TTL.
        client.balance(&alice);
    }

    #[test]
    fn test_secure_transfer_refreshes_ttl() {
        use crate::secure::SecureTokenClient;

        let env = Env::default();
        env.ledger().set_min_persistent_entry_ttl(5);
        env.ledger().set_max_entry_ttl(20);

        let contract_id = env.register_contract(None, secure::SecureToken);
        let client = SecureTokenClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&alice, &500);
        client.mint(&bob, &100);
        pin_contract_instance(&env, &contract_id);

        env.ledger().set_sequence_number(16);

        env.as_contract(&contract_id, || {
            assert_eq!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Balance(alice.clone())),
                4
            );
            assert_eq!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Balance(bob.clone())),
                4
            );
        });

        client.transfer(&alice, &bob, &50);

        env.as_contract(&contract_id, || {
            assert_eq!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Balance(alice.clone())),
                20
            );
            assert_eq!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Balance(bob.clone())),
                20
            );
        });

        assert_eq!(client.balance(&alice), 450);
        assert_eq!(client.balance(&bob), 150);
    }
}
