# `vulnerable/unsafe_cast`

## Vulnerability: Unsafe Integer Cast

**Severity:** High

## Description

The contract casts between integer types (e.g. `u64 as i64` or `i128 as u64`) without range validation. A value that is valid in the source type may be negative or truncated in the target type, silently corrupting balances or reward calculations.

## Exploit Scenario

1. A balance of `u64::MAX` is cast to `i64`, producing `-1`.
2. Subsequent arithmetic treats the balance as negative.
3. Attacker exploits the corrupted value to withdraw more than they deposited.

## Vulnerable Code

```rust
let signed_amount = raw_amount as i64; // ❌ wraps if raw_amount > i64::MAX
```

## Secure Fix

```rust
let signed_amount = i64::try_from(raw_amount)
    .expect("amount exceeds i64::MAX"); // ✅
```

No separate secure crate — the fix is using `try_from` / `try_into` with explicit error handling.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
