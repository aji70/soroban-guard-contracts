//! Mock Oracle contract for testing.

use soroban_sdk::{contractclient, contracttype, Address, Env};

#[contracttype]
pub enum OracleDataKey {
    Admin,
    Price,
    LastUpdated,
}

// Client interface — generated on all platforms (wasm and native).
#[contractclient(name = "MockOracleClient")]
pub trait OracleTrait {
    fn init(env: Env, admin: Address);
    fn set_price(env: Env, price: i128);
    fn get_price(env: Env) -> i128;
    fn last_updated(env: Env) -> u64;
}

// Actual mock implementation — only compiled on native (test) builds.
#[cfg(not(target_family = "wasm"))]
mod mock_impl {
    use super::OracleDataKey;
    use soroban_sdk::{contract, contractimpl, Address, Env};

    #[contract]
    pub struct MockOracle;

    #[contractimpl]
    impl MockOracle {
        pub fn init(env: Env, admin: Address) {
            if env.storage().persistent().has(&OracleDataKey::Admin) {
                panic!("already initialized");
            }
            env.storage()
                .persistent()
                .set(&OracleDataKey::Admin, &admin);
        }

        pub fn set_price(env: Env, price: i128) {
            let admin: Address = env
                .storage()
                .persistent()
                .get(&OracleDataKey::Admin)
                .expect("admin not initialized");
            admin.require_auth();
            env.storage()
                .persistent()
                .set(&OracleDataKey::Price, &price);
            let now = env.ledger().timestamp();
            env.storage()
                .persistent()
                .set(&OracleDataKey::LastUpdated, &now);
        }

        pub fn get_price(env: Env) -> i128 {
            env.storage()
                .persistent()
                .get(&OracleDataKey::Price)
                .unwrap_or(0)
        }

        pub fn last_updated(env: Env) -> u64 {
            env.storage()
                .persistent()
                .get(&OracleDataKey::LastUpdated)
                .unwrap_or(0)
        }
    }
}

#[cfg(not(target_family = "wasm"))]
pub use mock_impl::MockOracle;
