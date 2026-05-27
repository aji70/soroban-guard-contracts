//! VULNERABLE: Permit Domain Missing
//!
//! A permit-style token where the signed payload contains only `(owner,
//! spender, amount)`.  Because the contract address and network passphrase are
//! absent from the message, the same signature is valid on every deployment of
//! this contract — a classic cross-contract signature replay.
//!
//! VULNERABILITY: `permit()` hashes only owner + spender + amount.  An
//! attacker who observes a valid permit on token-A can replay it verbatim
//! against token-B (or any future re-deployment) to authorise a spend they
//! never intended.
//!
//! SECURE MIRROR: `secure::SecureToken` binds the payload to
//! `(contract_id, network_id, nonce, deadline, "permit", owner, spender, amount)`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, xdr::ToXdr, Address, Bytes, BytesN, Env};

pub mod secure;

// ── Storage keys ──────────────────────────────────────────────────────────────

#[contracttype]
pub enum DataKey {
    Balance(Address),
    Allowance(Address, Address),
    Nonce(Address),
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn get_balance(env: &Env, account: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(account.clone()))
        .unwrap_or(0)
}

pub fn set_balance(env: &Env, account: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Balance(account.clone()), &amount);
}

pub fn get_allowance(env: &Env, owner: &Address, spender: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Allowance(owner.clone(), spender.clone()))
        .unwrap_or(0)
}

pub fn set_allowance(env: &Env, owner: &Address, spender: &Address, amount: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::Allowance(owner.clone(), spender.clone()), &amount);
}

pub fn get_nonce(env: &Env, account: &Address) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Nonce(account.clone()))
        .unwrap_or(0)
}

pub fn inc_nonce(env: &Env, account: &Address) {
    let n = get_nonce(env, account);
    env.storage()
        .persistent()
        .set(&DataKey::Nonce(account.clone()), &(n + 1));
}

/// Build the permit digest that the owner must sign.
///
/// ❌ BUG: payload omits contract address and network passphrase.
///    `hash(owner_bytes || spender_bytes || amount_bytes)`
///    is identical across every deployment — replay is trivial.
pub fn vulnerable_permit_digest(
    env: &Env,
    owner: &Address,
    spender: &Address,
    amount: i128,
) -> BytesN<32> {
    let mut msg = Bytes::new(env);
    msg.append(&owner.clone().to_xdr(env));
    msg.append(&spender.clone().to_xdr(env));
    msg.append(&Bytes::from_array(env, &amount.to_be_bytes()));
    env.crypto().sha256(&msg).into()
}

// ── Vulnerable token ──────────────────────────────────────────────────────────

#[contract]
pub struct VulnerableToken;

#[contractimpl]
impl VulnerableToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let bal = get_balance(&env, &to);
        set_balance(&env, &to, bal + amount);
    }

    /// ❌ The digest passed to the signature check has no domain separator.
    ///    The same `(owner, spender, amount, sig)` tuple is accepted by every
    ///    deployment of this contract on every network.
    ///
    /// The scanner fixture uses `require_auth` to represent the off-chain
    /// signature check; the exploitable flaw is in `vulnerable_permit_digest`
    /// which the scanner detects by inspecting what fields are hashed.
    pub fn permit(
        env: Env,
        owner: Address,
        spender: Address,
        amount: i128,
        _sig: BytesN<64>,
    ) {
        // Simulate: off-chain verifier checked sig over vulnerable_permit_digest.
        // require_auth stands in for that check in the test environment.
        owner.require_auth();
        // ❌ No nonce consumed — also replayable, but the primary flaw is the
        //    missing domain separator in vulnerable_permit_digest above.
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

    /// Expose the digest so tests can assert it contains no contract/network id.
    pub fn permit_digest(env: Env, owner: Address, spender: Address, amount: i128) -> BytesN<32> {
        vulnerable_permit_digest(&env, &owner, &spender, amount)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

    fn setup_two_tokens(
        env: &Env,
    ) -> (
        VulnerableTokenClient<'static>,
        VulnerableTokenClient<'static>,
    ) {
        let id_a = env.register_contract(None, VulnerableToken);
        let id_b = env.register_contract(None, VulnerableToken);
        (
            VulnerableTokenClient::new(env, &id_a),
            VulnerableTokenClient::new(env, &id_b),
        )
    }

    /// The permit digest produced by token-A and token-B are identical for the
    /// same (owner, spender, amount) tuple — the domain separator is absent.
    #[test]
    fn test_digest_is_identical_across_deployments() {
        let env = Env::default();
        env.mock_all_auths();
        let (token_a, token_b) = setup_two_tokens(&env);

        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let amount: i128 = 500;

        let digest_a = token_a.permit_digest(&owner, &spender, &amount);
        let digest_b = token_b.permit_digest(&owner, &spender, &amount);

        // ❌ Both digests are equal — a signature over digest_a is also valid
        //    for digest_b, enabling cross-contract replay.
        assert_eq!(digest_a, digest_b);
    }

    /// Demonstrate the vulnerable path: the same permit call succeeds on both
    /// token-A and token-B because the digest has no contract-address binding.
    #[test]
    fn test_vulnerable_allowance_set_without_domain() {
        let env = Env::default();
        env.mock_all_auths();

        let (token_a, token_b) = setup_two_tokens(&env);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);

        token_a.mint(&owner, &1000);
        token_b.mint(&owner, &1000);

        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);

        token_a.permit(&owner, &spender, &500, &dummy_sig);
        // ❌ Replay the identical call on token-B — succeeds because the
        //    digest has no contract-address binding.
        token_b.permit(&owner, &spender, &500, &dummy_sig);

        assert_eq!(token_a.allowance(&owner, &spender), 500);
        // ❌ token-B also has the allowance set — the permit was replayed.
        assert_eq!(token_b.allowance(&owner, &spender), 500);
    }

    /// Boundary: the allowance set by permit is usable for transfer_from.
    #[test]
    fn test_permit_then_transfer_from_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let id = env.register_contract(None, VulnerableToken);
        let client = VulnerableTokenClient::new(&env, &id);
        let owner = Address::generate(&env);
        let spender = Address::generate(&env);
        let recipient = Address::generate(&env);

        client.mint(&owner, &1000);
        let dummy_sig = BytesN::from_array(&env, &[0u8; 64]);
        client.permit(&owner, &spender, &300, &dummy_sig);

        client.transfer_from(&spender, &owner, &recipient, &300);
        assert_eq!(client.balance(&owner), 700);
        assert_eq!(client.balance(&recipient), 300);
    }
}
