# `vulnerable/div_by_zero`

## Vulnerability: Division by Zero

**Severity:** High

## Description

A fee or rate calculation divides by a value that can be zero (e.g. total supply, pool size, or a user-supplied denominator). When the divisor is zero, the contract panics with an uncontrolled trap, potentially bricking the contract or enabling a DoS.

## Exploit Scenario

1. Attacker drains the pool to zero (or the pool starts empty).
2. Any user calls a function that divides by the pool size.
3. Contract panics; the function is unusable until the pool is refilled.

## Vulnerable Code

```rust
let fee = total_fees / total_shares; // ❌ panics if total_shares == 0
```

## Secure Fix

```rust
assert!(total_shares > 0, "no shares outstanding"); // ✅
let fee = total_fees / total_shares;
```

No separate secure crate — the fix is an inline guard.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
