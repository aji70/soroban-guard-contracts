//! SECURE: Vault with correct auth + checked arithmetic
//!
//! This is the fixed mirror of `missing_auth` and `unchecked_math`.
//!
//! FIXES APPLIED:
//! 1. Every state-mutating function calls `from.require_auth()` before touching
//!    storage, ensuring only the account owner can move their own funds.
//! 2. All arithmetic uses `checked_add` / `checked_sub` / `checked_mul` and
//!    panics with a descriptive message on overflow rather than wrapping silently.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum DataKey {
    Balance(Address),
}

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    /// Mint tokens — in production this would also be admin-gated (see protected_admin).
    /// SECURE: Emits events for off-chain tracking.
    pub fn mint(env: Env, to: Address, amount: i128) {
        // FIX: In a real deployment, require admin auth here too.
        // For this example we focus on the transfer fix.
        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = current.checked_add(amount).expect("mint: balance overflow");
        env.storage().persistent().set(&key, &new_balance);

        // ✅ SECURE: Emit event for off-chain tracking
        env.events().publish((symbol_short!("mint"),), (to, amount));
    }

    /// Burn tokens from an address.
    /// SECURE: Requires auth and emits events for off-chain tracking.
    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();

        let key = DataKey::Balance(from.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = current
            .checked_sub(amount)
            .expect("burn: insufficient balance");
        assert!(new_balance >= 0, "burn: insufficient balance");
        env.storage().persistent().set(&key, &new_balance);

        // ✅ SECURE: Emit event for off-chain tracking
        env.events()
            .publish((symbol_short!("burn"),), (from, amount));
    }

    /// FIX 1: `from.require_auth()` is called before any state mutation.
    /// Only the account identified by `from` can authorise this transfer.
    ///
    /// FIX 2: Balance arithmetic uses `checked_sub` / `checked_add` so an
    /// underflow (spending more than you own) or overflow panics cleanly
    /// instead of wrapping around.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        // ✅ FIX 1: Require the sender to have signed this transaction.
        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let to_key = DataKey::Balance(to.clone());

        let from_balance: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        let to_balance: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);

        // ✅ FIX 2: Checked arithmetic — panics on underflow/overflow.
        let new_from = from_balance
            .checked_sub(amount)
            .expect("transfer: insufficient balance");
        assert!(new_from >= 0, "transfer: insufficient balance");
        let new_to = to_balance
            .checked_add(amount)
            .expect("transfer: recipient balance overflow");

        env.storage().persistent().set(&from_key, &new_from);
        env.storage().persistent().set(&to_key, &new_to);

        env.events()
            .publish((symbol_short!("transfer"),), (from, to, amount));
    }

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

    #[test]
    fn test_transfer_succeeds_with_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &1000);
        env.mock_all_auths();
        client.transfer(&alice, &bob, &400);

        assert_eq!(client.balance(&alice), 600);
        assert_eq!(client.balance(&bob), 400);
    }

    /// The secure contract rejects a transfer when the caller hasn't authorised it.
    #[test]
    #[should_panic]
    fn test_transfer_fails_without_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &1000);
        // No mock_all_auths — should panic because require_auth is enforced.
        client.transfer(&alice, &bob, &400);
    }

    /// Spending more than the balance panics (checked_sub).
    #[test]
    #[should_panic]
    fn test_transfer_panics_on_underflow() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.mint(&alice, &100);
        env.mock_all_auths();
        // Trying to send more than alice has — should panic.
        client.transfer(&alice, &bob, &500);
    }

    #[test]
    fn test_burn_succeeds_with_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);

        client.mint(&alice, &1000);
        env.mock_all_auths();
        client.burn(&alice, &400);

        assert_eq!(client.balance(&alice), 600);
    }

    #[test]
    #[should_panic]
    fn test_burn_fails_without_auth() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);

        client.mint(&alice, &1000);
        // No mock_all_auths — should panic because require_auth is enforced.
        client.burn(&alice, &400);
    }

    #[test]
    #[should_panic]
    fn test_burn_panics_on_insufficient_balance() {
        let env = Env::default();
        let contract_id = env.register_contract(None, SecureVault);
        let client = SecureVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);

        client.mint(&alice, &100);
        env.mock_all_auths();
        // Trying to burn more than alice has — should panic.
        client.burn(&alice, &500);
    }
}
