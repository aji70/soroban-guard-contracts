//! VULNERABLE: Contract Emits Events with Sensitive Balance Data
//!
//! A token contract that publishes post-transfer balances for both sender and
//! recipient in every transfer event. Off-chain indexers and anyone monitoring
//! the ledger can reconstruct every account's full transaction history and
//! current balance from the event stream alone — no storage access required.
//!
//! VULNERABILITY: `transfer()` emits `(from, to, new_from_balance, new_to_balance)`
//! leaking exact financial state of both parties after every transaction.
//!
//! SECURE MIRROR: `secure::SecureToken` emits only `(from, to, amount)` —
//! the transfer amount is public by necessity, but post-transfer balances are not.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

pub(crate) fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

// ── Vulnerable token ──────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    /// Mint `amount` tokens to `to`. No auth check — for test setup.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current + amount);
    }

    /// VULNERABLE: transfers `amount` and emits post-transfer balances of both parties.
    /// Any ledger observer can reconstruct full account histories from the event stream.
    ///
    /// # Vulnerability
    /// Event payload includes `new_from_balance` and `new_to_balance`. Impact: full privacy leak.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_bal = get_balance(&env, &from);
        assert!(from_bal >= amount, "insufficient balance");

        let new_from_balance = from_bal - amount;
        let new_to_balance = get_balance(&env, &to) + amount;

        set_balance(&env, &from, new_from_balance);
        set_balance(&env, &to, new_to_balance);

        // ❌ Leaks post-transfer balances of both parties to the event stream.
        // Anyone monitoring the ledger can reconstruct full account histories
        // and current balances without any storage access.
        env.events().publish(
            (symbol_short!("transfer"),),
            (from.clone(), to.clone(), new_from_balance, new_to_balance),
        );
    }

    /// Returns the balance of `account`, defaulting to 0.
    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env, TryFromVal, Val, Vec,
    };

    fn setup() -> (Env, VulnerableTokenClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &id);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1000);
        client.mint(&bob, &200);
        (env, client, alice, bob)
    }

    /// Transfer emits an event that contains post-transfer balance values.
    /// Demonstrates the privacy leak — exact balances are visible on-chain.
    #[test]
    fn test_transfer_emits_balance_values() {
        let (env, client, alice, bob) = setup();
        client.transfer(&alice, &bob, &400);

        assert_eq!(client.balance(&alice), 600);
        assert_eq!(client.balance(&bob), 600);

        // ❌ The event payload exposes exact post-transfer balances.
        // new_from_balance=600, new_to_balance=600 are visible to all observers.
        let events = env.events().all();
        assert_eq!(events.len(), 1, "expected exactly one transfer event");

        // Decode the event data tuple and verify it contains balance values.
        let event_data: Val = events.last().unwrap().2;
        let tuple =
            Vec::<Val>::try_from_val(&env, &event_data).expect("event data should be a tuple/vec");

        // A 4-element tuple means balances were leaked (from, to, from_bal, to_bal).
        assert_eq!(
            tuple.len(),
            4,
            "event must contain 4 fields including leaked balances"
        );

        // Decode the leaked balance fields (indices 2 and 3).
        let leaked_from_bal = i128::try_from_val(&env, &tuple.get(2).unwrap())
            .expect("third field should be i128 balance");
        let leaked_to_bal = i128::try_from_val(&env, &tuple.get(3).unwrap())
            .expect("fourth field should be i128 balance");

        assert_eq!(
            leaked_from_bal, 600,
            "event leaks alice's post-transfer balance"
        );
        assert_eq!(
            leaked_to_bal, 600,
            "event leaks bob's post-transfer balance"
        );
    }
}
