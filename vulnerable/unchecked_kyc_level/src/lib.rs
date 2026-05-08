//! VULNERABLE: Unchecked KYC Level
//!
//! A KYC contract that stores a `kyc_level: u32` per user without validating
//! that the value falls within the defined range (0–3). An admin can set
//! `kyc_level = 999`, which downstream access-control checks may interpret as
//! a super-privileged level not intended by the protocol design, creating an
//! undocumented privilege escalation path.
//!
//! VULNERABILITY: No upper-bound check on `level` in `set_kyc_level` —
//! any u32 value including 999 or u32::MAX is accepted and stored.
//!
//! SEVERITY: Medium

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

pub mod secure;

pub const MAX_KYC_LEVEL: u32 = 3;

#[contracttype]
pub enum DataKey {
    Admin,
    KycLevel(Address),
}

#[contract]
pub struct UncheckedKycLevel;

#[contractimpl]
impl UncheckedKycLevel {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// VULNERABLE: `level` is unchecked — 999 or u32::MAX is accepted and
    /// stored, enabling undocumented privilege escalation.
    pub fn set_kyc_level(env: Env, user: Address, level: u32) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        // ❌ Missing: if level > MAX_KYC_LEVEL { panic!("kyc_level out of range") }
        env.storage()
            .persistent()
            .set(&DataKey::KycLevel(user), &level);
    }

    pub fn get_kyc_level(env: Env, user: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::KycLevel(user))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, UncheckedKycLevelClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, UncheckedKycLevel);
        let client = UncheckedKycLevelClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, id, client)
    }

    /// Demonstrates the vulnerability: kyc_level = 999 is accepted and stored.
    #[test]
    fn test_out_of_range_level_accepted() {
        let (env, _id, client) = setup();
        let user = Address::generate(&env);

        client.set_kyc_level(&user, &999);
        assert_eq!(client.get_kyc_level(&user), 999, "out-of-range level was stored");
    }

    /// Secure version panics for any level above MAX_KYC_LEVEL.
    #[test]
    #[should_panic(expected = "kyc_level out of range")]
    fn test_secure_rejects_out_of_range_level() {
        use crate::secure::SecureKycClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureKyc);
        let client = SecureKycClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let user = Address::generate(&env);
        client.set_kyc_level(&user, &(MAX_KYC_LEVEL + 1));
    }

    /// Secure version accepts all valid levels 0 through MAX_KYC_LEVEL.
    #[test]
    fn test_secure_accepts_all_valid_levels() {
        use crate::secure::SecureKycClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureKyc);
        let client = SecureKycClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        for level in 0..=MAX_KYC_LEVEL {
            let user = Address::generate(&env);
            client.set_kyc_level(&user, &level);
            assert_eq!(client.get_kyc_level(&user), level);
        }
    }
}
