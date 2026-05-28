#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

const MAX_BONUS_BPS: i128 = 1500; // 15% cap for secure path

#[contract]
pub struct UncappedLiquidationBonus;

#[contractimpl]
impl UncappedLiquidationBonus {
    /// BUG: liquidation payout uses unbounded bonus basis points.
    /// The fixture should make this unsafe path reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = (env, actor, amount);
    }

    /// Returns collateral seized for a given debt repaid and bonus bps.
    pub fn vulnerable_liquidate(debt_repaid: i128, bonus_bps: i128) -> i128 {
        // BUG: no cap on bonus_bps; governance can set 10000 bps (100%)
        debt_repaid + (debt_repaid * bonus_bps / 10_000)
    }

    pub fn secure_set_bonus(bonus_bps: i128) -> i128 {
        if bonus_bps > MAX_BONUS_BPS {
            panic!("bonus exceeds maximum allowed");
        }
        bonus_bps
    }

    pub fn secure_liquidate(debt_repaid: i128, bonus_bps: i128) -> i128 {
        let safe_bps = Self::secure_set_bonus(bonus_bps);
        debt_repaid + (debt_repaid * safe_bps / 10_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_extreme_bonus_seizes_excess_collateral() {
        let seized = UncappedLiquidationBonus::vulnerable_liquidate(1000, 10_000);
        assert_eq!(seized, 2000);
    }

    #[test]
    fn test_boundary_bonus_just_above_cap_should_fail_but_passes_vulnerable() {
        let seized = UncappedLiquidationBonus::vulnerable_liquidate(1000, 1501);
        assert!(seized > 1150);
    }

    #[test]
    #[should_panic(expected = "bonus exceeds maximum allowed")]
    fn test_secure_rejects_bonus_above_cap() {
        UncappedLiquidationBonus::secure_liquidate(1000, 10_000);
    }

    #[test]
    fn test_secure_allows_valid_bonus() {
        let seized = UncappedLiquidationBonus::secure_liquidate(1000, 1000);
        assert_eq!(seized, 1100);
    }
}
