use crate::DataKey;
use soroban_sdk::{Address, Env, Map};

/// Secure fix: snapshot voting power at proposal start; mark has-voted.
pub fn secure_vote(env: &Env, actor: Address, snapshot: &Map<Address, i128>) {
    let mut votes: Map<Address, i128> = env
        .storage()
        .instance()
        .get(&DataKey::Votes)
        .unwrap_or(Map::new(env));
    if votes.contains_key(actor.clone()) {
        panic!("already voted");
    }
    let power = snapshot.get(actor.clone()).unwrap_or(0);
    votes.set(actor, power);
    env.storage().instance().set(&DataKey::Votes, &votes);
}
