use super::DataKey;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

#[contracttype]
pub enum SecureDataKey {
    /// Explicitly accepted donation amount available for admin to skim.
    TotalDonations,
}

#[contract]
pub struct SecureSkimVault;

#[contractimpl]
impl SecureSkimVault {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::TotalAccounted, &0i128);
        env.storage().persistent().set(&DataKey::RawBalance, &0i128);
        env.storage()
            .persistent()
            .set(&SecureDataKey::TotalDonations, &0i128);
    }

    pub fn deposit(env: Env, user: Address, amount: i128) {
        user.require_auth();
        assert!(amount > 0, "amount must be positive");
        let acc: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::TotalAccounted)
            .unwrap_or(0);
        let raw: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::TotalAccounted, &(acc + amount));
        env.storage()
            .persistent()
            .set(&DataKey::RawBalance, &(raw + amount));
        env.events()
            .publish((symbol_short!("deposit"),), (user, amount));
    }

    /// Simulate accounting drift (same helper as the vulnerable contract).
    pub fn inject_excess(env: Env, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let raw: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::RawBalance, &(raw + amount));
    }

    /// SECURE: explicit donation acceptance. Only donated amounts are skimmable.
    pub fn donate(env: Env, donor: Address, amount: i128) {
        donor.require_auth();
        assert!(amount > 0, "amount must be positive");
        let donations: i128 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::TotalDonations)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&SecureDataKey::TotalDonations, &(donations + amount));
        env.events()
            .publish((symbol_short!("donate"),), (donor, amount));
    }

    /// SECURE: only explicitly donated amounts may be skimmed.
    /// Unexplained excess in the raw balance is never treated as admin-owned.
    pub fn skim(env: Env) -> i128 {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();

        let donations: i128 = env
            .storage()
            .persistent()
            .get(&SecureDataKey::TotalDonations)
            .unwrap_or(0);

        if donations <= 0 {
            return 0;
        }

        // ✅ Only the explicitly accepted donation amount is removed.
        env.storage()
            .persistent()
            .set(&SecureDataKey::TotalDonations, &0i128);
        let raw: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::RawBalance, &(raw - donations));
        env.events()
            .publish((symbol_short!("skim"),), (admin, donations));
        donations
    }

    pub fn redeemable(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::TotalAccounted)
            .unwrap_or(0)
    }

    pub fn raw_balance(env: Env) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::RawBalance)
            .unwrap_or(0)
    }
}
