//! VULNERABLE: Ignored Return Value from Sub-Call
//!
//! An escrow contract that calls an external token contract's `transfer()`
//! to release funds to a recipient. The return value (and any panic from the
//! token contract) is silently discarded with `let _ = ...`.
//!
//! Because the state update (`Released = true`) happens unconditionally after
//! the ignored call, a failed token transfer still marks the escrow as
//! released. The recipient never receives funds, but the escrow is permanently
//! locked — the funds are stuck and the release flag cannot be reset.
//!
//! VULNERABILITY: `let _ = token_client.transfer(...)` swallows the result.
//! State is mutated regardless of whether the token transfer succeeded.
//!
//! SECURE MIRROR: `secure::SecureEscrow` propagates the call without
//! discarding the result, so a panicking token contract rolls back the entire
//! transaction and the escrow state is never updated.
//!
//! SEVERITY: High

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;
pub mod token;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    /// Address of the token contract used for payouts.
    TokenId,
    /// Address that will receive the escrowed funds on release.
    Recipient,
    /// Amount held in escrow.
    Amount,
    /// True once `release` has been called.
    Released,
    /// The escrow depositor / owner who can trigger release.
    Owner,
}

// ── Token client interface ────────────────────────────────────────────────────

pub mod token_interface {
    use soroban_sdk::{contractclient, Address, Env};

    /// Minimal interface for an ERC-20-style token contract.
    #[contractclient(name = "TokenClient")]
    pub trait Token {
        fn transfer(env: Env, from: Address, to: Address, amount: i128);
    }
}

// ── Vulnerable escrow ─────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableEscrow;

#[contractimpl]
impl VulnerableEscrow {
    /// Initialise the escrow with a token, recipient, and locked amount.
    ///
    /// # Panics
    /// Panics if the escrow has already been initialised.
    pub fn initialize(
        env: Env,
        owner: Address,
        token_id: Address,
        recipient: Address,
        amount: i128,
    ) {
        owner.require_auth();
        assert!(
            !env.storage().persistent().has(&DataKey::Released),
            "already initialized"
        );
        env.storage()
            .persistent()
            .set(&DataKey::Owner, &owner);
        env.storage()
            .persistent()
            .set(&DataKey::TokenId, &token_id);
        env.storage()
            .persistent()
            .set(&DataKey::Recipient, &recipient);
        env.storage()
            .persistent()
            .set(&DataKey::Amount, &amount);
        env.storage()
            .persistent()
            .set(&DataKey::Released, &false);
    }

    /// Release escrowed funds to the recipient.
    ///
    /// VULNERABLE: the token `transfer` return value is discarded with
    /// `let _ = ...`. If the token contract panics or returns an error the
    /// Soroban host would normally roll back the transaction — but by
    /// explicitly ignoring the result we signal to the compiler that we do
    /// not care about the outcome. In a scenario where the token contract
    /// returns a non-panicking error value (e.g. a `Result`), the escrow
    /// marks itself as released even though no tokens moved.
    pub fn release(env: Env) {
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner)
            .unwrap();
        owner.require_auth();

        let released: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Released)
            .unwrap_or(false);
        assert!(!released, "already released");

        let token_id: Address = env
            .storage()
            .persistent()
            .get(&DataKey::TokenId)
            .unwrap();
        let recipient: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Recipient)
            .unwrap();
        let amount: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Amount)
            .unwrap();

        // ❌ Return value ignored — if the token transfer fails (e.g. the
        //    token contract returns a Result::Err or the call is mocked to
        //    do nothing), the escrow still marks itself as released.
        let _ = token_interface::TokenClient::new(&env, &token_id)
            .transfer(&env.current_contract_address(), &recipient, &amount);

        // State is updated unconditionally — funds may never have moved.
        env.storage()
            .persistent()
            .set(&DataKey::Released, &true);
    }

    /// Returns `true` if the escrow has been released.
    pub fn is_released(env: Env) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::Released)
            .unwrap_or(false)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};
    use token::MockToken;

    fn setup(env: &Env, should_fail: bool) -> (
        VulnerableEscrowClient,
        Address, // owner
        Address, // recipient
        Address, // escrow contract id
    ) {
        let token_id = env.register_contract(None, MockToken);
        let token_client = token::MockTokenClient::new(env, &token_id);
        token_client.set_fail(&should_fail);

        let escrow_id = env.register_contract(None, VulnerableEscrow);
        let client = VulnerableEscrowClient::new(env, &escrow_id);

        let owner = Address::generate(env);
        let recipient = Address::generate(env);

        // Mint tokens to the escrow contract so it has funds to release.
        token_client.mint(&escrow_id, &500);

        client.initialize(&owner, &token_id, &recipient, &500);

        (client, owner, recipient, escrow_id)
    }

    /// Normal release: token transfer succeeds and escrow is marked released.
    #[test]
    fn test_normal_release_works() {
        let env = Env::default();
        env.mock_all_auths();

        let (client, _owner, _recipient, _escrow_id) = setup(&env, false);

        assert!(!client.is_released());
        client.release();
        assert!(client.is_released());
    }

    /// Demonstrates the vulnerability: even when the token transfer is
    /// configured to silently fail (no-op), the escrow still marks itself
    /// as released. The recipient receives nothing, but the escrow is
    /// permanently locked.
    #[test]
    fn test_failed_sub_call_still_marks_escrow_released() {
        let env = Env::default();
        env.mock_all_auths();

        // Configure the mock token to silently do nothing on transfer.
        let (client, _owner, _recipient, _escrow_id) = setup(&env, true);

        assert!(!client.is_released());

        // Release is called — the token transfer silently fails (no-op),
        // but the escrow still marks itself as released.
        client.release();

        // BUG: escrow is released even though no tokens were transferred.
        assert!(
            client.is_released(),
            "escrow marked released despite failed token transfer"
        );
    }
}
