#![no_std]
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct AbstainCountsAsYes;

#[contractimpl]
impl AbstainCountsAsYes {
    /// BUG: support calculation treats abstain as yes.
    /// The fixture should make this unsafe path reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: soroban_sdk::Address, amount: i128) {
        let _ = (env, actor, amount);
    }

    pub fn vulnerable_passes(yes: i128, no: i128, abstain: i128) -> bool {
        // BUG: abstain counted on yes side
        (yes + abstain) > no
    }

    pub fn secure_passes(yes: i128, no: i128, abstain: i128, quorum: i128) -> bool {
        // Secure: abstain counts toward quorum only; yes must exceed no
        let total = yes + no + abstain;
        total >= quorum && yes > no
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_abstain_flips_result() {
        assert!(AbstainCountsAsYes::vulnerable_passes(40, 60, 30));
    }

    #[test]
    fn test_boundary_abstain_exactly_bridges_gap() {
        assert!(AbstainCountsAsYes::vulnerable_passes(50, 51, 1));
    }

    #[test]
    fn test_secure_rejects_when_yes_less_than_no() {
        assert!(!AbstainCountsAsYes::secure_passes(40, 60, 30, 100));
    }

    #[test]
    fn test_secure_passes_when_yes_exceeds_no_and_quorum_met() {
        assert!(AbstainCountsAsYes::secure_passes(70, 20, 10, 90));
    }
}
