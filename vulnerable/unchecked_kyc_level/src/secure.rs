use soroban_sdk::{contract, contractimpl, Address, Env};
use super::{DataKey, MAX_KYC_LEVEL};

#[contract]
pub struct SecureKyc;

#[contractimpl]
impl SecureKyc {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// SECURE: enforces that `level` is within the defined range [0, MAX_KYC_LEVEL],
    /// preventing undocumented privilege escalation via out-of-range values.
    pub fn set_kyc_level(env: Env, user: Address, level: u32) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        // ✅ Reject any level outside the defined protocol range.
        if level > MAX_KYC_LEVEL {
            panic!("kyc_level out of range");
        }

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
