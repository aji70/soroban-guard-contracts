#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

/// Health factor expressed as fixed-point with 4 decimals.
/// 1_0000 = 1.0 (exactly at liquidation threshold).
/// > 1_0000 = healthy; < 1_0000 = undercollateralised.
const HEALTH_FACTOR_ONE: i128 = 1_0000;

#[contract]
pub struct InvertedHealthFactor;

#[contractimpl]
impl InvertedHealthFactor {
    /// BUG: liquidation guard uses the wrong comparison direction.
    /// The fixture should make this unsafe path reachable and easy to scan.
    pub fn vulnerable_entry(env: Env, actor: Address, amount: i128) {
        let _ = (env, actor, amount);
    }

    /// Returns true if liquidation is permitted (vulnerable).
    pub fn vulnerable_can_liquidate(collateral: i128, debt: i128) -> bool {
        let health = (collateral * HEALTH_FACTOR_ONE) / debt;
        // BUG: inverted; allows liquidation when healthy (health > 1)
        health > HEALTH_FACTOR_ONE
    }

    /// Returns true if liquidation is permitted (secure).
    pub fn secure_can_liquidate(collateral: i128, debt: i128) -> bool {
        let health = (collateral * HEALTH_FACTOR_ONE) / debt;
        // Correct: only allow when undercollateralised
        health < HEALTH_FACTOR_ONE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerable_allows_liquidation_of_healthy_position() {
        assert!(InvertedHealthFactor::vulnerable_can_liquidate(200, 100));
    }

    #[test]
    fn test_vulnerable_rejects_unhealthy_position() {
        assert!(!InvertedHealthFactor::vulnerable_can_liquidate(80, 100));
    }

    #[test]
    fn test_secure_rejects_healthy_position() {
        assert!(!InvertedHealthFactor::secure_can_liquidate(200, 100));
    }

    #[test]
    fn test_secure_allows_unhealthy_position() {
        assert!(InvertedHealthFactor::secure_can_liquidate(80, 100));
    }
}
