# `vulnerable/double_claim`

## Vulnerability: Double-Claim (Stale Timestamp)

**Severity:** Critical

## Description

`claim_rewards` computes rewards based on elapsed ledgers since `staked_at`, but never resets `staked_at` after paying out. The same elapsed window can be claimed repeatedly, draining the reward pool.

## Exploit Scenario

1. Staker stakes tokens; `staked_at` is recorded.
2. Staker waits N ledgers, then calls `claim_rewards` — receives reward for N ledgers.
3. Staker calls `claim_rewards` again immediately — receives the same reward again because `staked_at` was not updated.
4. Staker repeats until the reward pool is empty.

## Vulnerable Code

```rust
pub fn claim_rewards(env: Env, staker: Address) -> u64 {
    let elapsed = env.ledger().sequence() - get_staked_at(&env, &staker);
    let reward = stake * rate * elapsed as u64;
    // ❌ Missing: set_staked_at(&env, &staker, env.ledger().sequence());
    reward
}
```

## Secure Fix

```rust
let reward = stake * rate * elapsed as u64;
set_staked_at(&env, &staker, env.ledger().sequence()); // ✅ reset window
reward
```

No separate secure crate — see the inline test in this crate demonstrating the fix.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
