use crate::DataKey;
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Env};

// ── Secure mirror ─────────────────────────────────────────────────────────────

#[contract]
pub struct SecureMintToken;

#[contractimpl]
impl SecureMintToken {
    /// Initialise the secure token with an admin address.
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: Only the stored admin can mint tokens.
    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("admin not initialized");
        // ✅ Admin must sign this transaction
        admin.require_auth();

        let key = DataKey::Balance(to.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));

        env.events().publish((symbol_short!("mint"),), (to, amount));
    }

    /// Returns the balance of `account` in the secure token, defaulting to 0.
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
    use soroban_sdk::testutils::Address as _;

    #[test]
    fn test_secure_admin_can_mint() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, SecureMintToken);
        let admin = Address::generate(&env);
        let client = SecureMintTokenClient::new(&env, &contract_id);

        client.initialize(&admin);
        client.mint(&admin, &500);
        assert_eq!(client.balance(&admin), 500);
    }

    #[test]
    #[should_panic]
    fn test_secure_attacker_cannot_mint() {
        let env = Env::default();
        // No mock_all_auths — auth failures will panic.
        let contract_id = env.register_contract(None, SecureMintToken);
        let admin = Address::generate(&env);
        let attacker = Address::generate(&env);
        let client = SecureMintTokenClient::new(&env, &contract_id);

        client.initialize(&admin);
        // ✅ This panics because attacker is not the admin.
        client.mint(&attacker, &999_999);
    }
}
