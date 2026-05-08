# `vulnerable/missing_ttl`

## Vulnerability: Storage Expiry (Missing TTL Renewal)

**Severity:** High

## Description

Persistent storage entries on Soroban have a time-to-live (TTL). This contract writes balances to persistent storage but never calls `extend_ttl()`. After enough ledgers pass, the balance entry expires and is deleted, causing users to lose their funds silently.

## Exploit Scenario

1. User deposits tokens; balance is written to persistent storage.
2. No activity occurs for the TTL window.
3. The storage entry expires; the user's balance is now `0` (default).
4. A subsequent transfer or withdrawal fails or succeeds with a zero balance.

## Vulnerable Code

```rust
env.storage().persistent().set(&key, &new_balance);
// ❌ Missing: env.storage().persistent().extend_ttl(&key, threshold, extend_to);
```

## Secure Fix

```rust
env.storage().persistent().set(&key, &new_balance);
env.storage().persistent().extend_ttl(&key, LOW_WATERMARK, HIGH_WATERMARK); // ✅
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
