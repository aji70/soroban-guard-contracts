# `vulnerable/unprotected_delete`

## Vulnerability: Unprotected Storage Delete

**Severity:** Critical

## Description

A function that wipes contract storage (or a user's data entry) is callable by any address without admin authorisation. An attacker can erase all contract state, effectively bricking the contract or wiping user balances.

## Exploit Scenario

1. Attacker calls `delete_all()` or `clear_user(victim)`.
2. Contract removes storage entries without verifying the caller is the admin.
3. All balances, configuration, or history is permanently deleted.

## Vulnerable Code

```rust
pub fn delete_all(env: Env) {
    // ❌ Missing: require_admin(&env);
    env.storage().persistent().remove(&DataKey::Balances);
}
```

## Secure Fix

```rust
pub fn delete_all(env: Env) {
    require_admin(&env); // ✅
    env.storage().persistent().remove(&DataKey::Balances);
}
```

No separate secure crate — the fix is an inline admin auth check.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
