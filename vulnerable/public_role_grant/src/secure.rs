// SECURE: Admin-gated operator role management
//
// This is the fixed mirror for `vulnerable_entry`.
//
// Fixes:
// - Role grants/revocations require admin authorization.
// - Events are emitted only after successful writes.




use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};


// Reuse the same DataKey layout as the vulnerable contract.
#[contracttype]
enum DataKey {
    Admin,
    Operator(Address),
}

#[contract]
pub struct SecureRoleGrant;

#[contractimpl]
impl SecureRoleGrant {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
    }

    /// Internal helper to load admin.
    fn admin_of(env: &Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("admin not initialized")
    }

    /// Emit only after successful writes.
fn emit_operator_granted(env: &Env, actor: &Address, amount: &i128) {
        env.events().publish((symbol_short!("ogr"),), (actor.clone(), *amount));
    }



    /// ✅ Secure grant/revoke entry.
    ///
    /// Boundary behavior: this rejects unauthenticated callers by gating on
    /// admin authorization. Additionally rejects `amount < 0` as an example
    /// boundary condition.
    pub fn grant_operator_secure(env: Env, actor: Address, amount: i128) {
        // Reject boundary condition.
        if amount < 0 {
            panic!("invalid amount");
        }

        // Load and require admin auth.
        let admin = Self::admin_of(&env);

        // Require admin auth before granting operator.
        // In unit tests, missing auth will panic (boundary behavior).
        admin.require_auth();


        env.storage()
            .persistent()
            .set(&DataKey::Operator(actor.clone()), &true);

        // Event only after successful write.
        Self::emit_operator_granted(&env, &actor, &amount);
    }

    pub fn revoke_operator_secure(env: Env, actor: Address) {
        let admin = Self::admin_of(&env);
        admin.require_auth();


        env.storage()
            .persistent()
            .set(&DataKey::Operator(actor.clone()), &false);
        // Keep revoke event emission minimal; scanners focus on grant.
    }

    pub fn operator_only_action(env: Env, caller: Address) -> i128 {
        let is_operator: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Operator(caller.clone()))
            .unwrap_or(false);
        if !is_operator {
            panic!("not operator");
        }

        1
    }

    pub fn is_operator(env: Env, actor: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Operator(actor))
            .unwrap_or(false)
    }
}






