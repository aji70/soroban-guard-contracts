use super::DataKey;
use soroban_sdk::{contract, contractimpl, Address, Bytes, Env};

#[contract]
pub struct SecureBridge;

#[contractimpl]
impl SecureBridge {
    pub fn initialize(env: Env) {
        env.storage()
            .persistent()
            .set(&DataKey::MintFails, &false);
    }

    pub fn set_mint_fails(env: Env, fails: bool) {
        env.storage()
            .persistent()
            .set(&DataKey::MintFails, &fails);
    }

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

    /// SECURE: marks the proof consumed *before* the external mint.
    /// If the mint panics, the Soroban transaction reverts atomically —
    /// the consumed flag is rolled back and the proof is not left in a
    /// partial state. Once the mint succeeds the consumed flag persists
    /// and replay is permanently blocked.
    pub fn redeem(env: Env, proof_id: Bytes, recipient: Address, amount: i128) {
        let used: bool = env
            .storage()
            .persistent()
            .get(&DataKey::ProofUsed(proof_id.clone()))
            .unwrap_or(false);
        if used {
            panic!("proof already consumed");
        }

        // ✅ Mark consumed before external effects.
        // A mint failure reverts this write atomically.
        env.storage()
            .persistent()
            .set(&DataKey::ProofUsed(proof_id), &true);

        // External mint — if this panics, the whole tx reverts.
        Self::do_mint(&env, &recipient, amount);
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
