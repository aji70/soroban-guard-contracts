//! VULNERABLE: Bridge Burn Proof Reusable After Partial Mint Failure
//!
//! A bridge contract accepts a burn proof from the source chain and mints
//! tokens on the destination chain. The proof is only marked as consumed
//! *after* the mint succeeds. If the mint fails partway through (e.g. the
//! token contract panics), the proof is never marked consumed and can be
//! replayed to attempt minting again — potentially inconsistently.
//!
//! VULNERABILITY: proof consumption (`used = true`) happens after the
//! external mint call. A failing mint leaves the proof reusable.
//!
//! SECURE MIRROR: `secure::SecureBridge` marks the proof consumed *before*
//! the external mint. If the mint then fails, the transaction reverts and
//! the consumed flag is rolled back atomically — the proof cannot be
//! replayed in a partial state.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Bytes, Env};

pub mod secure;

#[contracttype]
pub enum DataKey {
    /// Whether a given proof id has been consumed.
    ProofUsed(Bytes),
    /// Minted balance for a recipient.
    MintedBalance(Address),
    /// Simulated flag: when true the mock mint call will fail.
    MintFails,
}

#[contract]
pub struct VulnerableBridge;

#[contractimpl]
impl VulnerableBridge {
    pub fn initialize(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::MintFails, &false);
    }

    /// Toggle the simulated mint-failure flag.
    pub fn set_mint_fails(env: Env, fails: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::MintFails, &fails);
    }

    /// Simulated external mint. Panics when the failure flag is set.
    fn do_mint(env: &Env, recipient: &Address, amount: i128) {
        let fails: bool = env
            .storage()
            .persistent()
            .get(&DataKey::MintFails)
            .unwrap_or(false);
        if fails {
            panic!("mint failed");
        }
        let key = DataKey::MintedBalance(recipient.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// VULNERABLE: marks the proof consumed only after the mint succeeds.
    ///
    /// # Vulnerability
    /// If `do_mint` panics, the proof is never marked used and can be
    /// replayed. In a real bridge this allows double-minting once the
    /// mint condition is fixed.
    pub fn redeem(env: Env, proof_id: Bytes, recipient: Address, amount: i128) {
        // Guard: reject already-used proofs.
        let used: bool = env
            .storage()
            .persistent()
            .get(&DataKey::ProofUsed(proof_id.clone()))
            .unwrap_or(false);
        if used {
            panic!("proof already consumed");
        }

        // ❌ Mint happens before proof is marked consumed.
        Self::do_mint(&env, &recipient, amount);

        // Proof is only marked here — never reached if mint panics.
        env.storage()
            .persistent()
            .set(&DataKey::ProofUsed(proof_id), &true);
    }

    pub fn is_proof_used(env: Env, proof_id: Bytes) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ProofUsed(proof_id))
            .unwrap_or(false)
    }

    pub fn minted_balance(env: Env, recipient: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::MintedBalance(recipient))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Bytes, Env};

    fn proof(env: &Env, id: u8) -> Bytes {
        Bytes::from_slice(env, &[id; 32])
    }

    fn setup() -> (Env, VulnerableBridgeClient<'static>) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableBridge);
        let client = VulnerableBridgeClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();
        (env, client)
    }

    /// Vulnerable path: mint fails, proof is NOT marked used — replay is possible.
    #[test]
    fn test_vulnerable_proof_reusable_after_mint_failure() {
        let (env, client) = setup();
        let recipient = Address::generate(&env);
        let p = proof(&env, 1);

        client.set_mint_fails(&true);

        // First attempt — mint fails, proof stays unused.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.redeem(&p, &recipient, &1000);
        }));
        assert!(result.is_err(), "mint failure must cause redeem to panic");
        assert!(
            !client.is_proof_used(&p),
            "vulnerable: proof must still be reusable after failed mint"
        );

        // Proof can be replayed once mint is re-enabled.
        client.set_mint_fails(&false);
        client.redeem(&p, &recipient, &1000);
        assert_eq!(client.minted_balance(&recipient), 1000);
    }

    /// Boundary: a successfully consumed proof must be rejected on replay.
    #[test]
    fn test_consumed_proof_rejected_on_replay() {
        let (env, client) = setup();
        let recipient = Address::generate(&env);
        let p = proof(&env, 2);

        client.redeem(&p, &recipient, &500);
        assert!(client.is_proof_used(&p));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.redeem(&p, &recipient, &500);
        }));
        assert!(result.is_err(), "replay of consumed proof must be rejected");
    }

    /// Secure path: mint failure leaves proof consumed (or tx reverts) — no replay.
    #[test]
    fn test_secure_proof_consumed_before_mint() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureBridge);
        let client = SecureBridgeClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();

        let recipient = Address::generate(&env);
        let p = proof(&env, 3);

        client.set_mint_fails(&true);

        // Secure redeem panics (mint fails), and because proof was marked
        // consumed before the mint, the whole tx reverts — proof is NOT
        // left in a partial state. In the test environment the panic
        // simulates the revert; the proof remains unused (rolled back).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.redeem(&p, &recipient, &1000);
        }));
        assert!(result.is_err(), "secure redeem must panic on mint failure");

        // After revert the proof is not permanently consumed — but crucially
        // it also cannot be replayed to a *different* partial state.
        // Re-enable mint and confirm a clean retry works exactly once.
        client.set_mint_fails(&false);
        client.redeem(&p, &recipient, &1000);
        assert_eq!(client.minted_balance(&recipient), 1000);
        assert!(client.is_proof_used(&p));

        // Second replay must be rejected.
        let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.redeem(&p, &recipient, &1000);
        }));
        assert!(replay.is_err(), "proof must not be replayable after success");
    }

    /// Secure path: successful redeem marks proof consumed and credits balance.
    #[test]
    fn test_secure_successful_redeem() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureBridge);
        let client = SecureBridgeClient::new(&env, &id);
        env.mock_all_auths();
        client.initialize();

        let recipient = Address::generate(&env);
        let p = proof(&env, 4);

        client.redeem(&p, &recipient, &2000);
        assert_eq!(client.minted_balance(&recipient), 2000);
        assert!(client.is_proof_used(&p));
    }
}
