# `vulnerable/zero_stake`

## Vulnerability: Zero-Value Stake

**Severity:** Medium

## Description

The staking contract accepts a stake of `0`. This creates a storage entry with no economic value, wastes ledger resources, and can cause division-by-zero errors in reward calculations that divide by total staked amount.

## Exploit Scenario

1. Attacker calls `stake(attacker, 0)` many times.
2. Each call creates a storage entry and may increment a staker count.
3. Reward calculations that divide by total stake encounter zero, causing a panic.

## Vulnerable Code

```rust
pub fn stake(env: Env, staker: Address, amount: u64) {
    staker.require_auth();
    // ❌ Missing: assert!(amount > 0, "stake must be positive");
    env.storage().persistent().set(&DataKey::Stake(staker), &amount);
}
```

## Secure Fix

```rust
assert!(amount > 0, "stake must be positive"); // ✅
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
