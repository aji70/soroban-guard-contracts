//! VULNERABLE: Admin Rug-Pull via Unilateral Forced Withdrawal
//!
//! An escrow contract where the admin can call `admin_withdraw(user, recipient)`
//! using only their own auth. The user whose funds are being drained is never
//! consulted, giving the admin unilateral power to rug-pull any depositor.
//!
//! VULNERABILITY: `admin_withdraw` only calls `require_auth` on the admin,
//! not on the `user` whose escrow balance is being emptied.
//!
//! SECURE MIRROR: `secure::SecureEscrow` requires the user to co-sign any
//! forced withdrawal, so the admin cannot act unilaterally.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

#[contract]
pub struct VulnerableEscrow;

#[contractimpl]
impl VulnerableEscrow {
    /// Initialise the escrow with an admin. Guards against re-init.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Deposit `amount` into the escrow for `user`. Requires user auth.
    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Withdraw `amount` from the escrow for `user`. Requires user auth.
    pub fn withdraw(env: Env, user: Address, amount: i128) {
        user.require_auth();
        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);
    }

    /// VULNERABLE: only admin auth is checked — the user whose funds are
    /// being moved has no say. Admin can drain any account at will.
    ///
    /// # Vulnerability
    /// Missing `user.require_auth()`. Impact: admin can rug-pull any depositor unilaterally.
    pub fn admin_withdraw(env: Env, user: Address, recipient: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        // ❌ Missing: user.require_auth();

        let key = DataKey::Balance(user.clone());
        let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = balance.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);

        let recipient_key = DataKey::Balance(recipient.clone());
        let recipient_bal: i128 = env.storage().persistent().get(&recipient_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&recipient_key, &(recipient_bal + amount));
    }

    /// Returns the balance of `user`, defaulting to 0.
    pub fn get_balance(env: Env, user: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(user))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableEscrowClient<'static>, Address) {
        let env = Env::default();
        let contract_id = env.register_contract(None, VulnerableEscrow);
        let client = VulnerableEscrowClient::new(&env, &contract_id);
        let admin = Address::generate(&env);
        env.mock_all_auths();
        client.initialize(&admin);
        (env, client, admin)
    }

    /// Demonstrates the vulnerability: admin drains user funds without user consent.
    #[test]
    fn test_admin_drains_user_without_user_auth() {
        let (env, client, _admin) = setup();

        let user = Address::generate(&env);
        let attacker_wallet = Address::generate(&env);

        client.deposit(&user, &1000);
        assert_eq!(client.get_balance(&user), 1000);

        // Admin calls admin_withdraw — no user auth required or checked.
        client.admin_withdraw(&user, &attacker_wallet, &1000);

        assert_eq!(client.get_balance(&user), 0);
        assert_eq!(client.get_balance(&attacker_wallet), 1000);
    }

    /// User has no mechanism to prevent the drain.
    #[test]
    fn test_user_cannot_prevent_admin_drain() {
        let (env, client, _admin) = setup();

        let user = Address::generate(&env);
        let recipient = Address::generate(&env);

        client.deposit(&user, &500);
        client.admin_withdraw(&user, &recipient, &500);

        assert_eq!(client.get_balance(&user), 0);
    }

    /// Secure version: admin_withdraw requires user co-signature.
    #[test]
    fn test_secure_rejects_admin_only_drain() {
        use crate::secure::SecureEscrowClient;
        use soroban_sdk::IntoVal;

        let env = Env::default();
        let contract_id = env.register_contract(None, secure::SecureEscrow);
        let client = SecureEscrowClient::new(&env, &contract_id);

        let admin = Address::generate(&env);
        let user = Address::generate(&env);
        let recipient = Address::generate(&env);

        env.mock_all_auths();
        client.initialize(&admin);
        client.deposit(&user, &1000);

        // Only mock admin auth — user has NOT authorised this call.
        env.mock_auths(&[soroban_sdk::testutils::MockAuth {
            address: &admin,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &contract_id,
                fn_name: "admin_withdraw",
                args: (user.clone(), recipient.clone(), 1000_i128).into_val(&env),
                sub_invokes: &[],
            },
        }]);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.admin_withdraw(&user, &recipient, &1000);
        }));

        assert!(result.is_err(), "must reject without user co-signature");
        assert_eq!(client.get_balance(&user), 1000, "funds must remain intact");
    }
}
