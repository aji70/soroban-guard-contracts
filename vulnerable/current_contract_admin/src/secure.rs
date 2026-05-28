use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Admin,
    PendingAdmin,
    Value,
}

#[contract]
pub struct SecureCurrentContractAdmin;

#[contractimpl]
impl SecureCurrentContractAdmin {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    pub fn initialize_required(env: Env, admin: Option<Address>) {
        let admin = admin.expect("admin required");
        Self::initialize(env, admin);
    }

    pub fn nominate_admin(env: Env, nominee: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::PendingAdmin, &nominee);
    }

    pub fn accept_admin(env: Env) {
        let pending: Address = env
            .storage()
            .persistent()
            .get(&DataKey::PendingAdmin)
            .expect("no pending admin");
        pending.require_auth();
        env.storage().persistent().set(&DataKey::Admin, &pending);
    }

    pub fn admin_action(env: Env) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        env.storage().persistent().set(&DataKey::Value, &1u32);
    }

    pub fn value(env: Env) -> u32 {
        env.storage().persistent().get(&DataKey::Value).unwrap_or(0)
    }
}
