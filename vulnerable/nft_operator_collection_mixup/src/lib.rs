//! VULNERABLE: NFT Operator Approval Accepts Wrong Collection Scope
//!
//! Operator approvals are keyed by `(owner, operator)` only. An approval
//! granted for one token can be reused to transfer any other token owned
//! by the same address, including tokens in completely different scopes.
//!
//! VULNERABILITY: `approve` and `transfer_from` use `DataKey::Approval(owner,
//! operator)` with no collection or token-id dimension, so a single approval
//! covers all tokens.
//!
//! SECURE MIRROR: `secure::SecureNft` keys approvals by
//! `(owner, operator, token_id)` so each approval is scoped to exactly
//! one token.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[cfg(not(target_family = "wasm"))]
pub mod secure;

#[contracttype]
pub enum DataKey {
    /// Token ownership: token_id -> owner
    Owner(u64),
    /// VULNERABLE: approval keyed only by (owner, operator) — no token scope.
    Approval(Address, Address),
}

#[contract]
pub struct VulnerableNft;

#[contractimpl]
impl VulnerableNft {
    /// Mint a token to `owner`. No auth required for test simplicity.
    pub fn mint(env: Env, owner: Address, token_id: u64) {
        if env.storage().persistent().has(&DataKey::Owner(token_id)) {
            panic!("token already exists");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &owner);
    }

    /// Approve `operator` to transfer tokens on behalf of `owner`.
    ///
    /// # Vulnerability
    /// Approval is stored without a token-id dimension. Approving for
    /// token A implicitly approves for every token owned by `owner`.
    pub fn approve(env: Env, owner: Address, operator: Address) {
        owner.require_auth();
        // ❌ No token_id in the key — approval covers all tokens.
        env.storage()
            .persistent()
            .set(&DataKey::Approval(owner, operator), &true);
    }

    /// Transfer `token_id` from `from` to `to`, accepting operator approval.
    ///
    /// # Vulnerability
    /// Checks `Approval(from, caller)` without verifying which token the
    /// approval was originally granted for.
    pub fn transfer_from(env: Env, caller: Address, from: Address, to: Address, token_id: u64) {
        caller.require_auth();

        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Owner(token_id))
            .expect("token does not exist");

        if owner != from {
            panic!("from is not the token owner");
        }

        // ❌ Approval check ignores which token the approval was for.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Approval(from.clone(), caller.clone()))
            .unwrap_or(false);

        if caller != owner && !approved {
            panic!("caller is not owner or approved operator");
        }

        env.storage()
            .persistent()
            .set(&DataKey::Owner(token_id), &to);
        // Approval is not cleared — operator retains access to all other tokens.
    }

    pub fn owner_of(env: Env, token_id: u64) -> Address {
        env.storage()
            .persistent()
            .get(&DataKey::Owner(token_id))
            .expect("token does not exist")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (Env, VulnerableNftClient<'static>, Address, Address) {
        let env = Env::default();
        let id = env.register_contract(None, VulnerableNft);
        let client = VulnerableNftClient::new(&env, &id);
        let owner = Address::generate(&env);
        let operator = Address::generate(&env);
        env.mock_all_auths();
        // Mint two tokens to owner.
        client.mint(&owner, &1);
        client.mint(&owner, &2);
        (env, client, owner, operator)
    }

    /// Vulnerable path: approval for token 1 lets operator transfer token 2.
    #[test]
    fn test_vulnerable_approval_for_one_token_transfers_another() {
        let (env, client, owner, operator) = setup();
        let recipient = Address::generate(&env);

        // Operator is approved — but only token 1 was intended.
        client.approve(&owner, &operator);

        // Operator transfers token 2, which was never explicitly approved.
        client.transfer_from(&operator, &owner, &recipient, &2);

        assert_eq!(client.owner_of(&2), recipient, "token 2 was stolen");
        // Token 1 is still with owner — only token 2 was taken.
        assert_eq!(client.owner_of(&1), owner);
    }

    /// Boundary: without any approval, transfer_from must be rejected.
    #[test]
    fn test_no_approval_blocks_transfer() {
        let (env, client, owner, operator) = setup();
        let recipient = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.transfer_from(&operator, &owner, &recipient, &1);
        }));
        assert!(result.is_err(), "transfer without approval must panic");
        assert_eq!(client.owner_of(&1), owner);
    }

    /// Secure path: approval for token 1 must not allow transfer of token 2.
    #[test]
    fn test_secure_approval_scoped_to_token() {
        use crate::secure::SecureNftClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureNft);
        let client = SecureNftClient::new(&env, &id);
        let owner = Address::generate(&env);
        let operator = Address::generate(&env);
        let recipient = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&owner, &1);
        client.mint(&owner, &2);

        // Approve operator for token 1 only.
        client.approve(&owner, &operator, &1);

        // Attempt to transfer token 2 — must be rejected.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.transfer_from(&operator, &owner, &recipient, &2);
        }));
        assert!(
            result.is_err(),
            "secure transfer must reject out-of-scope token"
        );
        assert_eq!(client.owner_of(&2), owner, "token 2 must remain with owner");
    }

    /// Secure path: approval for token 1 allows transfer of token 1.
    #[test]
    fn test_secure_approval_allows_correct_token() {
        use crate::secure::SecureNftClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureNft);
        let client = SecureNftClient::new(&env, &id);
        let owner = Address::generate(&env);
        let operator = Address::generate(&env);
        let recipient = Address::generate(&env);
        env.mock_all_auths();

        client.mint(&owner, &1);
        client.approve(&owner, &operator, &1);
        client.transfer_from(&operator, &owner, &recipient, &1);

        assert_eq!(client.owner_of(&1), recipient);
    }
}
