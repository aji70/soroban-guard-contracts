//! VULNERABLE: Bridge Validator Set Update Has No Quorum Check
//!
//! The bridge maintains a set of validators and a threshold for mint
//! approvals. The `update_validators` function accepts a new validator set
//! if it is signed by any single current validator. A single compromised
//! key is enough to replace the entire validator set and subsequently mint
//! arbitrary wrapped assets.
//!
//! VULNERABILITY: `update_validators` verifies exactly one signature from
//! the current set instead of requiring a threshold quorum.
//!
//! SECURE MIRROR: `secure::SecureBridge` requires at least `threshold`
//! distinct valid signatures from the current validator set before
//! applying any changes.

#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, vec, Bytes, BytesN, Env, Vec};

pub mod secure;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Simulated signature: SHA-256 of the payload.
pub fn make_sig(env: &Env, payload: &Bytes) -> BytesN<32> {
    env.crypto().sha256(payload).into()
}

pub fn verify_sig(env: &Env, payload: &Bytes, sig: &BytesN<32>) {
    let expected: BytesN<32> = env.crypto().sha256(payload).into();
    if expected != *sig {
        panic!("invalid signature");
    }
}

/// Build a deterministic "validator key" from a seed byte for tests.
pub fn validator_key(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

// ---------------------------------------------------------------------------
// Storage keys
// ---------------------------------------------------------------------------

#[contracttype]
pub enum DataKey {
    /// Current validator public keys.
    Validators,
    /// Minimum signatures required for mint approval.
    Threshold,
    /// Minted balance per recipient.
    Balance(BytesN<32>),
}

// ---------------------------------------------------------------------------
// Vulnerable contract
// ---------------------------------------------------------------------------

#[contract]
pub struct VulnerableBridge;

#[contractimpl]
impl VulnerableBridge {
    pub fn initialize(env: Env, validators: Vec<BytesN<32>>, threshold: u32) {
        if env.storage().persistent().has(&DataKey::Validators) {
            panic!("already initialized");
        }
        if threshold == 0 || threshold as usize > validators.len() as usize {
            panic!("invalid threshold");
        }
        env.storage()
            .persistent()
            .set(&DataKey::Validators, &validators);
        env.storage()
            .persistent()
            .set(&DataKey::Threshold, &threshold);
    }

    /// VULNERABLE: replaces the validator set if signed by any single validator.
    ///
    /// # Vulnerability
    /// Only one signature is checked. A single compromised validator can
    /// replace the entire set and take over the bridge.
    pub fn update_validators(
        env: Env,
        new_validators: Vec<BytesN<32>>,
        new_threshold: u32,
        signer_key: BytesN<32>,
        sig: BytesN<32>,
    ) {
        let validators: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&DataKey::Validators)
            .expect("not initialized");

        // ❌ Only one signer is verified — no quorum required.
        let mut signer_found = false;
        for v in validators.iter() {
            if v == signer_key {
                signer_found = true;
                break;
            }
        }
        if !signer_found {
            panic!("signer is not a current validator");
        }

        let mut payload = Bytes::new(&env);
        for v in new_validators.iter() {
            payload.append(&Bytes::from_array(&env, &v.to_array()));
        }
        payload.extend_from_array(&new_threshold.to_be_bytes());
        verify_sig(&env, &payload, &sig);

        env.storage()
            .persistent()
            .set(&DataKey::Validators, &new_validators);
        env.storage()
            .persistent()
            .set(&DataKey::Threshold, &new_threshold);
    }

    pub fn get_validators(env: Env) -> Vec<BytesN<32>> {
        env.storage()
            .persistent()
            .get(&DataKey::Validators)
            .unwrap_or(vec![&env])
    }

    pub fn get_threshold(env: Env) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::Threshold)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::{vec, Bytes, BytesN, Env, Vec};

    fn setup(env: &Env) -> (VulnerableBridgeClient<'static>, Vec<BytesN<32>>) {
        let id = env.register_contract(None, VulnerableBridge);
        let client = VulnerableBridgeClient::new(env, &id);
        let validators = vec![
            env,
            validator_key(env, 0x01),
            validator_key(env, 0x02),
            validator_key(env, 0x03),
        ];
        client.initialize(&validators, &2u32); // threshold = 2
        (client, validators)
    }

    fn sign_update(env: &Env, new_validators: &Vec<BytesN<32>>, new_threshold: u32) -> BytesN<32> {
        let mut payload = Bytes::new(env);
        for v in new_validators.iter() {
            payload.append(&Bytes::from_array(env, &v.to_array()));
        }
        payload.extend_from_array(&new_threshold.to_be_bytes());
        make_sig(env, &payload)
    }

    /// Vulnerable path: one validator signature replaces the entire set.
    #[test]
    fn test_vulnerable_single_sig_replaces_validator_set() {
        let env = Env::default();
        let (client, _) = setup(&env);

        let attacker_key = validator_key(&env, 0xAA);
        let new_set = vec![&env, attacker_key.clone()];
        let sig = sign_update(&env, &new_set, 1u32);

        // Only validator 0x01 signs — threshold is 2 but not enforced.
        client.update_validators(&new_set, &1u32, &validator_key(&env, 0x01), &sig);

        let updated = client.get_validators();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated.get(0).unwrap(), attacker_key);
        assert_eq!(client.get_threshold(), 1);
    }

    /// Boundary: non-validator signer is rejected even in the vulnerable contract.
    #[test]
    fn test_non_validator_signer_rejected() {
        let env = Env::default();
        let (client, _) = setup(&env);

        let outsider = validator_key(&env, 0xFF);
        let new_set = vec![&env, outsider.clone()];
        let sig = sign_update(&env, &new_set, 1u32);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_validators(&new_set, &1u32, &outsider, &sig);
        }));
        assert!(result.is_err(), "non-validator must be rejected");
    }

    /// Secure path: single validator signature is insufficient for update.
    #[test]
    fn test_secure_rejects_single_sig_update() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureBridge);
        let client = SecureBridgeClient::new(&env, &id);

        let validators = vec![
            &env,
            validator_key(&env, 0x01),
            validator_key(&env, 0x02),
            validator_key(&env, 0x03),
        ];
        client.initialize(&validators, &2u32);

        let attacker_key = validator_key(&env, 0xAA);
        let new_set = vec![&env, attacker_key.clone()];

        // Build payload and sign with only one validator.
        let mut payload = Bytes::new(&env);
        for v in new_set.iter() {
            payload.append(&Bytes::from_array(&env, &v.to_array()));
        }
        payload.extend_from_array(&1u32.to_be_bytes());
        let sig1 = make_sig(&env, &payload);

        let sigs = vec![&env, sig1];
        let signers = vec![&env, validator_key(&env, 0x01)];

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_validators(&new_set, &1u32, &signers, &sigs);
        }));
        assert!(result.is_err(), "secure: single sig must not meet quorum");

        // Validator set must be unchanged.
        assert_eq!(client.get_validators().len(), 3);
    }

    /// Secure path: quorum of signatures allows the update.
    #[test]
    fn test_secure_accepts_quorum_update() {
        use crate::secure::SecureBridgeClient;

        let env = Env::default();
        let id = env.register_contract(None, secure::SecureBridge);
        let client = SecureBridgeClient::new(&env, &id);

        let validators = vec![
            &env,
            validator_key(&env, 0x01),
            validator_key(&env, 0x02),
            validator_key(&env, 0x03),
        ];
        client.initialize(&validators, &2u32);

        let new_key = validator_key(&env, 0x04);
        let new_set = vec![&env, new_key.clone()];

        let mut payload = Bytes::new(&env);
        for v in new_set.iter() {
            payload.append(&Bytes::from_array(&env, &v.to_array()));
        }
        payload.extend_from_array(&1u32.to_be_bytes());

        // Two validators sign — meets threshold of 2.
        let sig1 = make_sig(&env, &payload);
        let sig2 = make_sig(&env, &payload);
        let sigs = vec![&env, sig1, sig2];
        let signers = vec![&env, validator_key(&env, 0x01), validator_key(&env, 0x02)];

        client.update_validators(&new_set, &1u32, &signers, &sigs);
        assert_eq!(client.get_validators().len(), 1);
        assert_eq!(client.get_validators().get(0).unwrap(), new_key);
    }
}
