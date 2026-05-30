#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, Val, Vec};

#[contracttype]
pub enum DataKey {
    Paused,
    Admin,
    LastEmergencyCall,
}

#[contract]
pub struct EmergencyDelayBypass;

#[contractimpl]
impl EmergencyDelayBypass {
    pub fn init(env: Env, admin: Address) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Paused, &false);
    }

    /// BUG: emergency dispatcher does not restrict function selectors or targets.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = amount;
        actor.require_auth();
        env.storage().instance().set(
            &DataKey::LastEmergencyCall,
            &Symbol::new(&env, "change_admin"),
        );
    }

    pub fn emergency_execute_vulnerable(
        env: Env,
        caller: Address,
        selector: Symbol,
        _args: Vec<Val>,
    ) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }
        env.storage()
            .instance()
            .set(&DataKey::LastEmergencyCall, &selector);
    }

    pub fn emergency_execute_secure(
        env: Env,
        caller: Address,
        selector: Symbol,
        _args: Vec<Val>,
    ) {
        caller.require_auth();
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        if caller != admin {
            panic!("not admin");
        }

        let pause = Symbol::new(&env, "pause");
        let unpause = Symbol::new(&env, "unpause");
        if selector != pause && selector != unpause {
            panic!("emergency path only allows pause/unpause");
        }

        env.storage()
            .instance()
            .set(&DataKey::LastEmergencyCall, &selector);
    }

    pub fn get_last_emergency_call(env: Env) -> Symbol {
        env.storage()
            .instance()
            .get(&DataKey::LastEmergencyCall)
            .unwrap_or(Symbol::new(&env, "none"))
    }

    pub fn is_paused(env: Env) -> bool {
        env.storage().instance().get(&DataKey::Paused).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, vec, Address, Env};

    fn setup(env: &Env) -> (Address, Address) {
        let contract_id = env.register_contract(None, EmergencyDelayBypass);
        let client = EmergencyDelayBypassClient::new(env, &contract_id);
        let admin = Address::generate(env);
        env.mock_all_auths();
        client.init(&admin);
        (contract_id, admin)
    }

    #[test]
    fn test_vulnerable_executes_non_pause_without_governance() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = EmergencyDelayBypassClient::new(&env, &contract_id);
        client.emergency_execute_vulnerable(
            &admin,
            &Symbol::new(&env, "change_admin"),
            &vec![&env],
        );
        assert_eq!(
            client.get_last_emergency_call(),
            Symbol::new(&env, "change_admin")
        );
    }

    #[test]
    fn test_boundary_pause_allowed_in_secure_path() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = EmergencyDelayBypassClient::new(&env, &contract_id);
        client.emergency_execute_secure(&admin, &Symbol::new(&env, "pause"), &vec![&env]);
        assert_eq!(client.get_last_emergency_call(), Symbol::new(&env, "pause"));
    }

    #[test]
    #[should_panic(expected = "emergency path only allows pause/unpause")]
    fn test_secure_rejects_non_allowlisted_selector() {
        let env = Env::default();
        let (contract_id, admin) = setup(&env);
        let client = EmergencyDelayBypassClient::new(&env, &contract_id);
        client.emergency_execute_secure(
            &admin,
            &Symbol::new(&env, "change_admin"),
            &vec![&env],
        );
    }

    #[test]
    #[should_panic(expected = "not admin")]
    fn test_secure_rejects_non_admin_caller() {
        let env = Env::default();
        let (contract_id, _admin) = setup(&env);
        let client = EmergencyDelayBypassClient::new(&env, &contract_id);
        let rogue = Address::generate(&env);
        client.emergency_execute_secure(&rogue, &Symbol::new(&env, "pause"), &vec![&env]);
    }
}
