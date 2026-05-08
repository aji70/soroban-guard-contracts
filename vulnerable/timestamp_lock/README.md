# `vulnerable/timestamp_lock`

## Vulnerability: Timestamp Manipulation

**Severity:** Medium

## Description

The contract uses `env.ledger().timestamp()` to enforce a time-lock. Stellar validators have limited but non-zero ability to influence the ledger close time. An attacker who controls a validator (or colludes with one) can manipulate the timestamp to bypass the lock early.

## Exploit Scenario

1. Contract enforces a 24-hour lock using `ledger().timestamp()`.
2. Attacker colludes with a validator to advance the timestamp by 24 hours in one ledger.
3. Lock is bypassed; attacker withdraws funds before the intended unlock time.

## Vulnerable Code

```rust
let now = env.ledger().timestamp();
assert!(now >= unlock_time, "still locked"); // ❌ timestamp is manipulable
```

## Secure Fix

```rust
let seq = env.ledger().sequence();
assert!(seq >= unlock_sequence, "still locked"); // ✅ sequence is monotonic and harder to manipulate
```

See [`secure/sequence_lock`](../../secure/sequence_lock) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
