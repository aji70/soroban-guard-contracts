//! SECURE: Events Emit Only Transfer Amount
//!
//! Identical transfer logic but the event payload contains only
//! `(from, to, amount)` — the transfer amount is public by necessity,
//! but post-transfer balances are never published.

use super::{get_balance, set_balance};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let current = get_balance(&env, &to);
        set_balance(&env, &to, current + amount);
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_bal = get_balance(&env, &from);
        assert!(from_bal >= amount, "insufficient balance");

        set_balance(&env, &from, from_bal - amount);
        set_balance(&env, &to, get_balance(&env, &to) + amount);

        // ✅ Emits only the transfer amount — post-transfer balances stay private.
        env.events().publish(
            (symbol_short!("transfer"),),
            (from.clone(), to.clone(), amount),
        );
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{
        testutils::{Address as _, Events},
        Address, Env, TryFromVal, Val, Vec,
    };

    fn setup() -> (Env, SecureTokenClient<'static>, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &id);
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        client.mint(&alice, &1000);
        client.mint(&bob, &200);
        (env, client, alice, bob)
    }

    /// Secure transfer emits only (from, to, amount) — no balance data.
    #[test]
    fn test_secure_transfer_emits_only_amount() {
        let (env, client, alice, bob) = setup();
        client.transfer(&alice, &bob, &400);

        let events = env.events().all();
        assert_eq!(events.len(), 1, "expected exactly one transfer event");

        let event_data: Val = events.last().unwrap().2;
        let tuple =
            Vec::<Val>::try_from_val(&env, &event_data).expect("event data should be a tuple/vec");

        // ✅ Only 3 fields: (from, to, amount) — no balance data.
        assert_eq!(tuple.len(), 3, "event must contain only (from, to, amount)");

        // ✅ The third field is the transfer amount, not a post-transfer balance.
        let emitted_amount = i128::try_from_val(&env, &tuple.get(2).unwrap())
            .expect("third field should be i128 amount");
        assert_eq!(emitted_amount, 400, "event should emit the transfer amount");
    }
}
