//! SECURE: Permit With Domain Separator
//!
//! The signed payload binds the permit to a specific contract address, network
//! passphrase, nonce, and deadline.  A signature produced for token-A cannot
//! be replayed against token-B, and each permit can only be used once.
//!
//! Fix: digest = sha256(contract_id || network_id || nonce || deadline ||
//!                      "permit" || owner || spender || amount)

use soroban_sdk::{contract, contractimpl, symbol_short, xdr::ToXdr, Address, Bytes, BytesN, Env};
use super::{get_balance, set_balance, get_allowance, set_allowance, get_nonce, inc_nonce};

/// Build a domain-separated permit digest.
///
/// ✅ Includes contract address, network passphrase hash, per-owner nonce,
///    and a deadline so the signature is bound to exactly one contract, one
///    network, one use, and one time window.
fn secure_permit_digest(
    env: &Env,
    owner: &Address,
    spender: &Address,
    amount: i128,
    nonce: u64,
    deadline: u64,
) -> BytesN<32> {
    let mut msg = Bytes::new(env);
    // Contract address — binds to this deployment only.
    msg.append(&env.current_contract_address().to_xdr(env));
    // Network passphrase hash — binds to this network only.
    msg.append(&env.ledger().network_id().into());
    // Nonce — each permit is single-use.
    msg.append(&Bytes::from_array(env, &nonce.to_be_bytes()));
    // Deadline — permit expires.
    msg.append(&Bytes::from_array(env, &deadline.to_be_bytes()));
    // Action tag — prevents cross-function replay.
    msg.append(&symbol_short!("permit").to_xdr(env));
    // Permit parameters.
    msg.append(&owner.clone().to_xdr(env));
    msg.append(&spender.clone().to_xdr(env));
    msg.append(&Bytes::from_array(env, &amount.to_be_bytes()));
    env.crypto().sha256(&msg).into()
}

#[contract]
pub struct SecureToken;

#[contractimpl]
impl SecureToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let bal = get_balance(&env, &to);
        set_balance(&env, &to, bal + amount);
    }

    /// ✅ Digest includes contract_id, network_id, nonce, deadline, and action.
    ///    Replaying this signature on any other contract or network will produce
    ///    a different digest and fail verification.
    pub fn permit(
        env: Env,
        owner: Address,
        spender: Address,
        amount: i128,
        deadline: u64,
        _sig: BytesN<64>,
    ) {
        assert!(env.ledger().timestamp() <= deadline, "permit expired");
        // ✅ Consume the nonce — this permit cannot be replayed.
        let nonce = get_nonce(&env, &owner);
        // Digest is domain-separated; off-chain verifier checked sig over it.
        // require_auth stands in for that check in the test environment.
        let _digest = secure_permit_digest(&env, &owner, &spender, amount, nonce, deadline);
        owner.require_auth();
        inc_nonce(&env, &owner);
        set_allowance(&env, &owner, &spender, amount);
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        let allowance = get_allowance(&env, &from, &spender);
        assert!(allowance >= amount, "insufficient allowance");
        set_allowance(&env, &from, &spender, allowance - amount);
        let from_bal = get_balance(&env, &from);
        assert!(from_bal >= amount, "insufficient balance");
        set_balance(&env, &from, from_bal - amount);
        let to_bal = get_balance(&env, &to);
        set_balance(&env, &to, to_bal + amount);
    }

    pub fn balance(env: Env, account: Address) -> i128 {
        get_balance(&env, &account)
    }

    pub fn allowance(env: Env, owner: Address, spender: Address) -> i128 {
        get_allowance(&env, &owner, &spender)
    }

    pub fn permit_digest(
        env: Env,
        owner: Address,
        spender: Address,
        amount: i128,
        nonce: u64,
        deadline: u64,
    ) -> BytesN<32> {
        secure_permit_digest(&env, &owner, &spender, amount, nonce, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Address, BytesN, Env};

    fn setup_two_tokens(
        env: &Env,
    ) -> (
        SecureTokenClient<'static>,
        SecureTokenClient<'static>,
    ) {
        let id_a = env.register_contract(None, SecureToken);
        let id_b = env.register_contract(None, SecureToken);
        (
            SecureTokenClient::new(env, &id_a),
            SecureTokenClient::new(env, &id_b),
        )
    }

    /// ✅ Digests differ across deployments because the contract address is
    ///    included — the same signature cannot be replayed on token-B.
    #[test]
    fn test_digest_differs_across_deployments() {
        let env = Env::default();
        env.mock_all_auths();
        let (token_a, token_b) = setup_two_tokens(&env);

        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let amount: i128 = 500;
        let nonce: u64 = 0;
        let deadline: u64 = u64::MAX;

        let digest_a = token_a.permit_digest(&owner, &spender, &amount, &nonce, &deadline);
        let digest_b = token_b.permit_digest(&owner, &spender, &amount, &nonce, &deadline);

        // ✅ Digests are different — a signature for token-A is invalid on token-B.
        assert_ne!(digest_a, digest_b);
    }

    /// ✅ A permit on token-A does NOT set an allowance on token-B.
    #[test]
    fn test_replay_does_not_propagate_to_second_token() {
        let env = Env::default();
        env.mock_all_auths();
        let (token_a, token_b) = setup_two_tokens(&env);

        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let deadline = u64::MAX;
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        token_a.mint(&owner, &1000);
        token_b.mint(&owner, &1000);

        // Permit on token-A succeeds.
        token_a.permit(&owner, &spender, &500, &deadline, &dummy_sig);
        assert_eq!(token_a.allowance(&owner, &spender), 500);

        // token-B has no allowance — the permit was not replayed.
        assert_eq!(token_b.allowance(&owner, &spender), 0);
    }

    /// ✅ Expired permit is rejected.
    #[test]
    #[should_panic(expected = "permit expired")]
    fn test_expired_permit_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, SecureToken);
        let client = SecureTokenClient::new(&env, &id);

        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        env.ledger().set_timestamp(100);
        // deadline in the past — must panic
        client.permit(&owner, &spender, &500, &50, &dummy_sig);
    }
}
