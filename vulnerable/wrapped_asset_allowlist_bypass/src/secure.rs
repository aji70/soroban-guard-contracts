//! SECURE mirror: Wrapped Asset Allowlist Bypass — fixed.
//!
//! The fix: `register_wrapper` verifies that the declared underlying asset is
//! already on the allowlist before storing the mapping. `deposit` then
//! resolves the wrapper → underlying mapping and re-checks the underlying,
//! so a wrapper can never smuggle an unsupported token into the vault.

use crate::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SecureVault;

#[contractimpl]
impl SecureVault {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn allow_token(env: Env, token: Address) {
        Self::require_admin(&env);
        env.storage()
            .persistent()
            .set(&DataKey::AllowedToken(token), &true);
    }

    /// ✅ Fixed: underlying must already be on the allowlist at registration time.
    pub fn register_wrapper(env: Env, wrapper: Address, underlying: Address) {
        let allowed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::AllowedToken(underlying.clone()))
            .unwrap_or(false);
        if !allowed {
            panic!("underlying asset not allowed");
        }
        env.storage()
            .persistent()
            .set(&DataKey::WrapperAsset(wrapper), &underlying);
    }

    /// ✅ Fixed: resolves wrapper → underlying and verifies the underlying is
    /// on the allowlist before crediting the deposit.
    pub fn deposit(env: Env, actor: Address, wrapper: Address, amount: i128) {
        actor.require_auth();
        if amount <= 0 {
            panic!("amount must be positive");
        }

        // Resolve the underlying asset for this wrapper.
        let underlying: Address = env
            .storage()
            .persistent()
            .get(&DataKey::WrapperAsset(wrapper))
            .expect("wrapper not registered");

        // ✅ Check the underlying, not the wrapper.
        let allowed: bool = env
            .storage()
            .persistent()
            .get(&DataKey::AllowedToken(underlying))
            .unwrap_or(false);
        if !allowed {
            panic!("underlying asset not allowed");
        }

        let key = DataKey::Balance(actor.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(account))
            .unwrap_or(0)
    }

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
    }
}
