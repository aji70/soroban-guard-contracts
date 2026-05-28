use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum SecureDataKey {
    Owner(u64),
    /// SECURE: approval keyed by (owner, operator, token_id) — exact scope.
    Approval(Address, Address, u64),
}

#[contract]
pub struct SecureNft;

#[contractimpl]
impl SecureNft {
    pub fn mint(env: Env, owner: Address, token_id: u64) {
        if env
            .storage()
            .persistent()
            .has(&SecureDataKey::Owner(token_id))
        {
            panic!("token already exists");
        }
        env.storage()
            .persistent()
            .set(&SecureDataKey::Owner(token_id), &owner);
    }

    /// SECURE: approval is scoped to a specific token_id.
    pub fn approve(env: Env, owner: Address, operator: Address, token_id: u64) {
        owner.require_auth();
        // ✅ Key includes token_id — approval cannot bleed to other tokens.
        env.storage()
            .persistent()
            .set(&SecureDataKey::Approval(owner, operator, token_id), &true);
    }

    /// SECURE: checks approval for the exact token being transferred.
    pub fn transfer_from(env: Env, caller: Address, from: Address, to: Address, token_id: u64) {
        caller.require_auth();

        let owner: Address = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Owner(token_id))
            .expect("token does not exist");

        if owner != from {
            panic!("from is not the token owner");
        }

        // ✅ Approval check is scoped to this specific token_id.
        let approved: bool = env
            .storage()
            .persistent()
            .get(&SecureDataKey::Approval(
                from.clone(),
                caller.clone(),
                token_id,
            ))
            .unwrap_or(false);

        if caller != owner && !approved {
            panic!("caller is not owner or approved operator for this token");
        }

        env.storage()
            .persistent()
            .set(&SecureDataKey::Owner(token_id), &to);
        // Clear the single-use approval after transfer.
        env.storage()
            .persistent()
            .remove(&SecureDataKey::Approval(from, caller, token_id));
    }

    pub fn owner_of(env: Env, token_id: u64) -> Address {
        env.storage()
            .persistent()
            .get(&SecureDataKey::Owner(token_id))
            .expect("token does not exist")
    }
}
