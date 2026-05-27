//! VULNERABLE: Self-Referential Fee Collector
//!
//! A fee contract where the admin can set the fee collector to the contract's
//! own address. Fees are then transferred back into the contract without any
//! internal accounting, trapping them permanently and distorting balance-based
//! logic (e.g. redemption calculations that read the contract's token balance).
//!
//! VULNERABILITY: `set_collector` accepts `env.current_contract_address()` as
//! a valid collector. Subsequent `collect_fee` calls send fees to the contract
//! itself with no ledger entry tracking the trapped amount.
//!
//! SECURE MIRROR: `secure::SecureFeeCollector` panics with
//! "collector cannot be the contract itself" when the caller attempts to set
//! the collector to the current contract address.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    Admin,
    Collector,
    Fees,
}

#[contract]
pub struct SelfFeeCollector;

#[contractimpl]
impl SelfFeeCollector {
    /// Initialise with an admin. Guards against re-initialisation.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().persistent().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().persistent().set(&DataKey::Admin, &admin);
        env.storage().persistent().set(&DataKey::Fees, &0i128);
    }

    /// Admin sets the fee collector address.
    ///
    /// VULNERABLE: no check prevents `collector == env.current_contract_address()`.
    pub fn set_collector(env: Env, collector: Address) {
        let admin: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Admin)
            .expect("not initialized");
        admin.require_auth();
        // ❌ Missing: assert!(collector != env.current_contract_address(), "collector cannot be the contract itself");
        env.storage()
            .persistent()
            .set(&DataKey::Collector, &collector);
    }

    /// Simulate a fee-generating action. The fee is recorded internally and
    /// an event is emitted representing the transfer to the collector.
    ///
    /// When the collector is the contract itself the fee is "sent" back to the
    /// contract with no accounting entry, trapping it permanently.
    pub fn collect_fee(env: Env, amount: i128) {
        assert!(amount > 0, "amount must be positive");
        let collector: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Collector)
            .expect("collector not set");

        // Accumulate fees in storage to represent the contract's internal balance.
        let fees: i128 = env.storage().persistent().get(&DataKey::Fees).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::Fees, &(fees + amount));

        // ❌ When collector == current_contract_address() the fee is "sent" to
        //    the contract itself. No separate accounting tracks this trapped
        //    amount, so it inflates the raw balance without being redeemable.
        env.events()
            .publish((symbol_short!("fee"),), (collector, amount));
    }

    /// Returns the accumulated fee balance tracked in storage.
    pub fn get_fees(env: Env) -> i128 {
        env.storage().persistent().get(&DataKey::Fees).unwrap_or(0)
    }

    pub fn get_collector(env: Env) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Collector)
            .expect("collector not set")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, Address, Address, SelfFeeCollectorClient<'static>) {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SelfFeeCollector);
        let client = SelfFeeCollectorClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);
        (env, id, admin, client)
    }

    /// Normal operation: collector is an external address, fees are tracked.
    #[test]
    fn test_normal_fee_collection() {
        let (env, _id, _admin, client) = setup();
        let collector = Address::generate(&env);
        client.set_collector(&collector);
        client.collect_fee(&100);
        assert_eq!(client.get_fees(), 100);
    }

    /// DEMONSTRATES VULNERABILITY: collector set to the contract itself.
    /// Fees accumulate in storage but are "sent" to the contract with no
    /// separate accounting — they are permanently trapped.
    #[test]
    fn test_self_collector_traps_fees() {
        let (env, id, _admin, client) = setup();

        // Set the collector to the contract's own address — the vulnerable path.
        client.set_collector(&id);
        assert_eq!(client.get_collector(), id);

        client.collect_fee(&200);
        client.collect_fee(&300);

        // Fees are recorded in storage but the collector IS the contract.
        // Any logic that reads the contract's token balance to compute
        // redeemable amounts will be distorted by this trapped value.
        assert_eq!(client.get_fees(), 500);
    }

    /// Boundary: setting collector to a normal address is always accepted.
    #[test]
    fn test_external_collector_accepted() {
        let (env, _id, _admin, client) = setup();
        let external = Address::generate(&env);
        client.set_collector(&external);
        assert_eq!(client.get_collector(), external);
    }

    /// SECURE: setting collector to the contract itself is rejected.
    #[test]
    #[should_panic(expected = "collector cannot be the contract itself")]
    fn test_secure_rejects_self_collector() {
        use crate::secure::SecureFeeCollectorClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureFeeCollector);
        let client = SecureFeeCollectorClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        // Attempt to set the contract itself as collector — must panic.
        client.set_collector(&id);
    }

    /// SECURE: normal collector is still accepted by the secure version.
    #[test]
    fn test_secure_accepts_external_collector() {
        use crate::secure::SecureFeeCollectorClient;

        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, secure::SecureFeeCollector);
        let client = SecureFeeCollectorClient::new(&env, &id);
        let admin = Address::generate(&env);
        client.initialize(&admin);

        let external = Address::generate(&env);
        client.set_collector(&external);
        assert_eq!(client.get_collector(), external);
    }
}
