//! # temp_config_storage
//!
//! **Vulnerability (High):** Critical configuration (admin, fee_rate, token
//! address) is stored in `env.storage().temporary()`. Temporary storage in
//! Soroban expires after a configurable TTL. Once the TTL lapses the config is
//! silently gone and every function that reads it will panic or misbehave.
//!
//! **Fix:** Store all critical config in `env.storage().persistent()`.
//! Reserve temporary storage only for ephemeral data (nonces, rate-limit
//! counters, etc.).

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

const TEMP_TTL: u32 = 100; // short TTL to make expiry observable in tests

#[contracttype]
pub enum DataKey {
    Admin,
    FeeRate,
}

#[contract]
pub struct FeeContract;

#[contractimpl]
impl FeeContract {
    // ── VULNERABLE initialize ────────────────────────────────────────────────

    /// **BUG:** config stored in temporary storage — expires after TTL.
    pub fn initialize_vulnerable(env: Env, admin: Address, fee_rate: i128) {
        if env.storage().temporary().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage()
            .temporary()
            .set(&DataKey::Admin, &admin);
        env.storage()
            .temporary()
            .extend_ttl(&DataKey::Admin, TEMP_TTL, TEMP_TTL);
        env.storage()
            .temporary()
            .set(&DataKey::FeeRate, &fee_rate);
        env.storage()
            .temporary()
            .extend_ttl(&DataKey::FeeRate, TEMP_TTL, TEMP_TTL);
    }

    pub fn get_admin_vulnerable(env: Env) -> Option<Address> {
        env.storage().temporary().get(&DataKey::Admin)
    }

    pub fn get_fee_rate_vulnerable(env: Env) -> Option<i128> {
        env.storage().temporary().get(&DataKey::FeeRate)
    }

    // ── FIXED initialize ─────────────────────────────────────────────────────

    /// **FIX:** config stored in persistent storage — survives ledger advancement.
    pub fn initialize(env: Env, admin: Address, fee_rate: i128) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::FeeRate, &fee_rate);
    }

    pub fn get_admin(env: Env) -> Option<Address> {
        env.storage().persistent().get(&DataKey::Admin)
    }

    pub fn get_fee_rate(env: Env) -> Option<i128> {
        env.storage().persistent().get(&DataKey::FeeRate)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, i128) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, FeeContract);
        let admin = Address::generate(&env);
        (env, id, admin, 250_i128) // fee_rate = 250 bps
    }

    /// Baseline: config in temporary storage is readable immediately after init.
    #[test]
    fn test_temp_config_readable_immediately() {
        let (env, id, admin, fee_rate) = setup();
        let client = FeeContractClient::new(&env, &id);

        client.initialize_vulnerable(&admin, &fee_rate);

        assert_eq!(client.get_admin_vulnerable(), Some(admin));
        assert_eq!(client.get_fee_rate_vulnerable(), Some(fee_rate));
    }

    /// BUG DEMO: advancing the ledger past the TTL causes config reads to
    /// return None.
    #[test]
    fn test_temp_config_lost_after_ttl() {
        let (env, id, admin, fee_rate) = setup();
        let client = FeeContractClient::new(&env, &id);

        client.initialize_vulnerable(&admin, &fee_rate);

        // Advance ledger sequence past the temporary TTL.
        env.ledger().with_mut(|l| {
            l.sequence_number += TEMP_TTL + 1;
        });

        // Config is now gone.
        assert_eq!(client.get_admin_vulnerable(), None);
        assert_eq!(client.get_fee_rate_vulnerable(), None);
    }

    /// FIX: persistent config survives ledger advancement.
    #[test]
    fn test_persistent_config_survives_ledger_advancement() {
        let (env, id, admin, fee_rate) = setup();
        let client = FeeContractClient::new(&env, &id);

        client.initialize(&admin, &fee_rate);

        // Advance ledger far beyond any TTL.
        env.ledger().with_mut(|l| {
            l.sequence_number += 1_000_000;
        });

        assert_eq!(client.get_admin(), Some(admin));
        assert_eq!(client.get_fee_rate(), Some(fee_rate));
    }
}
