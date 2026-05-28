#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Map};

mod secure;

#[contracttype]
pub enum DataKey {
    Votes,
    Balances,
}

#[contract]
pub struct TransferDoubleVote;

#[contractimpl]
impl TransferDoubleVote {
    pub fn init(env: Env, voter: Address, balance: i128) {
        let mut balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        balances.set(voter, balance);
        env.storage().instance().set(&DataKey::Balances, &balances);
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        let mut balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        let from_bal = balances.get(from.clone()).unwrap_or(0);
        balances.set(from, from_bal - amount);
        let to_bal = balances.get(to.clone()).unwrap_or(0);
        balances.set(to, to_bal + amount);
        env.storage().instance().set(&DataKey::Balances, &balances);
    }

    /// BUG: live balances allow the same tokens to vote twice.
    /// The fixture should make this unsafe path reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = amount;
        let mut votes: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Votes)
            .unwrap_or(Map::new(&env));
        let balances: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Balances)
            .unwrap_or(Map::new(&env));
        // BUG: reads live balance, no snapshot, no has-voted guard
        let power = balances.get(actor.clone()).unwrap_or(0);
        let current = votes.get(actor.clone()).unwrap_or(0);
        votes.set(actor, current + power);
        env.storage().instance().set(&DataKey::Votes, &votes);
    }

    pub fn total_votes(env: Env) -> i128 {
        let votes: Map<Address, i128> = env
            .storage()
            .instance()
            .get(&DataKey::Votes)
            .unwrap_or(Map::new(&env));
        let mut total = 0i128;
        for (_, v) in votes.iter() {
            total += v;
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Address, Env};

    #[test]
    fn test_vulnerable_double_vote() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TransferDoubleVote);
        let client = TransferDoubleVoteClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let bob = Address::generate(&env);

        client.init(&alice, &100);
        client.vulnerable_entry(&alice, &0);
        client.transfer(&alice, &bob, &100);
        client.vulnerable_entry(&bob, &0);
        assert_eq!(client.total_votes(), 200);
    }

    #[test]
    fn test_boundary_zero_balance_no_votes() {
        let env = Env::default();
        let contract_id = env.register_contract(None, TransferDoubleVote);
        let client = TransferDoubleVoteClient::new(&env, &contract_id);
        let carol = Address::generate(&env);
        client.vulnerable_entry(&carol, &0);
        assert_eq!(client.total_votes(), 0);
    }
}
