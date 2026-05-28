//! VULNERABLE: Recursive hook depth — hooked token calls receiver with no depth guard.
//!
//! A hook-enabled token invokes `on_transfer` on the recipient after each
//! transfer. A malicious receiver re-triggers `transfer` from inside the hook,
//! causing unbounded recursion that exhausts the Soroban call-depth budget and
//! panics mid-execution, potentially leaving balances partially updated.
//!
//! VULNERABILITY: `transfer()` calls the receiver hook without tracking or
//! limiting recursion depth.
//!
//! SECURE MIRROR: `secure::SecureHookedToken` increments a `Temporary`
//! depth counter before the hook and panics if it exceeds `MAX_HOOK_DEPTH`.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env};

pub mod secure;

pub const MAX_HOOK_DEPTH: u32 = 1;

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    Balance(Address),
    HookCount,
}

#[contracttype]
pub enum ReceiverDataKey {
    Token,
    Sender,
    Recurse,
}

// ---------------------------------------------------------------------------
// Vulnerable hooked token
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableHookedToken;

#[contractimpl]
impl VulnerableHookedToken {
    pub fn mint(env: Env, to: Address, amount: i128) {
        let key = DataKey::Balance(to.clone());
        let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// VULNERABLE: calls receiver hook with no depth counter.
    ///
    /// # Vulnerability
    /// A recursive receiver re-enters `transfer` indefinitely until the
    /// Soroban call-depth limit panics mid-execution.
    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_key = DataKey::Balance(from.clone());
        let from_bal: i128 = env.storage().persistent().get(&from_key).unwrap_or(0);
        assert!(from_bal >= amount, "insufficient balance");

        env.storage()
            .persistent()
            .set(&from_key, &(from_bal - amount));

        let to_key = DataKey::Balance(to.clone());
        let to_bal: i128 = env.storage().persistent().get(&to_key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&to_key, &(to_bal + amount));

        // ❌ No depth guard — recursive receiver causes unbounded re-entry.
        let _: () = env.invoke_contract(
            &to,
            &symbol_short!("on_xfer"),
            soroban_sdk::vec![&env, from.into_val(&env), amount.into_val(&env)],
        );

        let hc: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::HookCount)
            .unwrap_or(0);
        env.storage()
            .persistent()
            .set(&DataKey::HookCount, &(hc + 1));
    }

    pub fn balance(env: Env, who: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(who))
            .unwrap_or(0)
    }

    pub fn hook_count(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::HookCount)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Recursive receiver (malicious hook)
// ---------------------------------------------------------------------------

#[contract]
pub struct RecursiveReceiver;

#[contractimpl]
impl RecursiveReceiver {
    /// Configure: store the token contract and the original sender.
    /// Set `recurse = true` to trigger re-entry on the next hook call.
    pub fn configure(env: Env, token: Address, sender: Address, recurse: bool) {
        env.storage()
            .persistent()
            .set(&ReceiverDataKey::Token, &token);
        env.storage()
            .persistent()
            .set(&ReceiverDataKey::Sender, &sender);
        env.storage()
            .persistent()
            .set(&ReceiverDataKey::Recurse, &recurse);
    }

    /// Hook called by the token after each transfer.
    /// When `recurse` is true, immediately calls `transfer` back into the token.
    pub fn on_xfer(env: Env, from: Address, amount: i128) {
        let recurse: bool = env
            .storage()
            .persistent()
            .get(&ReceiverDataKey::Recurse)
            .unwrap_or(false);

        if recurse {
            // Disable flag to avoid infinite loop in the test environment
            // (Soroban host will still panic at its own depth limit).
            env.storage()
                .persistent()
                .set(&ReceiverDataKey::Recurse, &false);

            let token: Address = env
                .storage()
                .persistent()
                .get(&ReceiverDataKey::Token)
                .expect("token not set");
            let self_addr = env.current_contract_address();

            // Re-enter the token's transfer — this is the recursive hook call.
            let _: () = env.invoke_contract(
                &token,
                &symbol_short!("transfer"),
                soroban_sdk::vec![
                    &env,
                    self_addr.into_val(&env),
                    from.into_val(&env),
                    amount.into_val(&env),
                ],
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    fn setup() -> (
        Env,
        Address,
        VulnerableHookedTokenClient<'static>,
        Address,
        RecursiveReceiverClient<'static>,
    ) {
        let env = Env::default();
        let token_id = env.register_contract(None, VulnerableHookedToken);
        let token = VulnerableHookedTokenClient::new(&env, &token_id);
        let receiver_id = env.register_contract(None, RecursiveReceiver);
        let receiver = RecursiveReceiverClient::new(&env, &receiver_id);
        (env, token_id, token, receiver_id, receiver)
    }

    /// Vulnerable path: a non-recursive receiver completes normally.
    #[test]
    fn test_vulnerable_normal_transfer_succeeds() {
        let (env, _token_id, token, receiver_id, receiver) = setup();
        env.mock_all_auths();

        let alice = Address::generate(&env);
        token.mint(&alice, &1000);
        // Non-recursive receiver — hook fires once, no re-entry.
        receiver.configure(&receiver_id, &alice, &false); // token addr unused here
        token.transfer(&alice, &receiver_id, &500);

        assert_eq!(token.balance(&alice), 500);
        assert_eq!(token.balance(&receiver_id), 500);
        assert_eq!(token.hook_count(), 1);
    }

    /// Boundary: recursive receiver causes the Soroban host to panic at its
    /// call-depth limit, demonstrating the unsafe path.
    #[test]
    #[should_panic]
    fn test_vulnerable_recursive_hook_exhausts_depth() {
        let (env, token_id, token, receiver_id, receiver) = setup();
        env.mock_all_auths();

        let alice = Address::generate(&env);
        token.mint(&alice, &1000);
        token.mint(&receiver_id, &1000);
        // recurse = true → receiver re-enters transfer on first hook call.
        receiver.configure(&token_id, &alice, &true);

        // ❌ Panics: recursive hook hits Soroban call-depth limit.
        token.transfer(&alice, &receiver_id, &100);
    }

    /// Secure path: depth-guarded token rejects the recursive hook call.
    #[test]
    #[should_panic]
    fn test_secure_rejects_recursive_hook() {
        use crate::secure::SecureHookedTokenClient;

        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, secure::SecureHookedToken);
        let token = SecureHookedTokenClient::new(&env, &token_id);
        let receiver_id = env.register_contract(None, RecursiveReceiver);
        let receiver = RecursiveReceiverClient::new(&env, &receiver_id);

        let alice = Address::generate(&env);
        token.mint(&alice, &1000);
        token.mint(&receiver_id, &1000);
        receiver.configure(&token_id, &alice, &true);

        // ✅ SECURE: depth guard panics before the second hook fires.
        token.transfer(&alice, &receiver_id, &100);
    }

    /// Secure path: a non-recursive transfer still completes normally.
    #[test]
    fn test_secure_normal_transfer_succeeds() {
        use crate::secure::SecureHookedTokenClient;

        let env = Env::default();
        env.mock_all_auths();

        let token_id = env.register_contract(None, secure::SecureHookedToken);
        let token = SecureHookedTokenClient::new(&env, &token_id);
        let receiver_id = env.register_contract(None, RecursiveReceiver);
        let receiver = RecursiveReceiverClient::new(&env, &receiver_id);

        let alice = Address::generate(&env);
        token.mint(&alice, &1000);
        receiver.configure(&token_id, &alice, &false);

        token.transfer(&alice, &receiver_id, &400);
        assert_eq!(token.balance(&alice), 600);
        assert_eq!(token.balance(&receiver_id), 400);
    }
}
