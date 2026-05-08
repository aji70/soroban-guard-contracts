# `vulnerable/uncapped_rate`

## Vulnerability: Uncapped Interest / Reward Rate

**Severity:** High

## Description

The admin can set the reward or interest rate to an arbitrarily large value. A malicious or compromised admin can set the rate to `u64::MAX`, causing the next reward claim to overflow or drain the entire pool in a single transaction.

## Exploit Scenario

1. Admin (or attacker who has taken over admin) calls `set_rate(u64::MAX)`.
2. Any staker calls `claim_rewards`; the reward calculation overflows or returns an enormous value.
3. The reward pool is drained in one transaction.

## Vulnerable Code

```rust
pub fn set_rate(env: Env, rate: u64) {
    require_admin(&env);
    // ❌ No upper bound on rate
    env.storage().persistent().set(&DataKey::Rate, &rate);
}
```

## Secure Fix

```rust
const MAX_RATE: u64 = 10_000; // 100% APR in basis points

pub fn set_rate(env: Env, rate: u64) {
    require_admin(&env);
    assert!(rate <= MAX_RATE, "rate exceeds maximum"); // ✅
    env.storage().persistent().set(&DataKey::Rate, &rate);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
