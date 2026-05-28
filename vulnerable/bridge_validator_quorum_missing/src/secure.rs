use super::DataKey;
use soroban_sdk::{contract, contractimpl, vec, Bytes, BytesN, Env, Vec};

#[contract]
pub struct SecureBridge;

#[contractimpl]
impl SecureBridge {
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

    /// SECURE: requires at least `threshold` distinct valid signatures from
    /// the current validator set before applying any changes.
    pub fn update_validators(
        env: Env,
        new_validators: Vec<BytesN<32>>,
        new_threshold: u32,
        signers: Vec<BytesN<32>>,
        sigs: Vec<BytesN<32>>,
    ) {
        let validators: Vec<BytesN<32>> = env
            .storage()
            .persistent()
            .get(&DataKey::Validators)
            .expect("not initialized");
        let threshold: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::Threshold)
            .expect("not initialized");

        if signers.len() != sigs.len() {
            panic!("signers and sigs length mismatch");
        }

        // Build the payload once.
        let mut payload = Bytes::new(&env);
        for v in new_validators.iter() {
            payload.append(&Bytes::from_array(&env, &v.to_array()));
        }
        payload.extend_from_array(&new_threshold.to_be_bytes());

        // ✅ Count distinct valid signatures from current validators.
        let mut valid_count = 0u32;
        let mut seen: Vec<BytesN<32>> = vec![&env];

        for i in 0..signers.len() {
            let signer = signers.get(i).unwrap();
            let sig = sigs.get(i).unwrap();

            // Must be a current validator.
            let mut is_validator = false;
            for v in validators.iter() {
                if v == signer {
                    is_validator = true;
                    break;
                }
            }
            if !is_validator {
                continue;
            }

            // Deduplicate signers.
            let mut already_seen = false;
            for s in seen.iter() {
                if s == signer {
                    already_seen = true;
                    break;
                }
            }
            if already_seen {
                continue;
            }

            // Verify the signature.
            let expected: BytesN<32> = env.crypto().sha256(&payload).into();
            if expected == sig {
                seen.push_back(signer);
                valid_count += 1;
            }
        }

        // ✅ Enforce quorum.
        if valid_count < threshold {
            panic!("insufficient validator signatures");
        }

        if new_threshold == 0 || new_threshold as usize > new_validators.len() as usize {
            panic!("invalid new threshold");
        }

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
