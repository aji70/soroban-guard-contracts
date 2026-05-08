# `vulnerable/unchecked_math`

## Vulnerability: Integer Overflow

**Severity:** High

## Description

Staking reward calculations use raw `*` on `u64` values. When the stake amount or elapsed ledgers are large, the multiplication silently wraps to a small number, allowing an attacker to claim far less (or far more) than they are owed.

## Exploit Scenario

1. Attacker stakes a large amount and waits many ledgers.
2. `claim_rewards` computes `stake * rate * elapsed` using unchecked arithmetic.
3. The product overflows `u64`, wrapping to near zero — reward pool is effectively stolen or the attacker receives an inflated payout depending on wrap direction.

## Vulnerable Code

```rust
let reward = stake * rate * elapsed; // ❌ silent overflow
```

## Secure Fix

```rust
let reward = stake
    .checked_mul(rate)
    .and_then(|v| v.checked_mul(elapsed))
    .expect("reward overflow"); // ✅
```

See [`secure/secure_vault`](../../secure/secure_vault) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
