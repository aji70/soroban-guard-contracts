# `vulnerable/key_collision`

## Vulnerability: Storage Key Collision

**Severity:** High

## Description

Two different data types (e.g. user balances and allowances) are stored under keys derived from the same address without a namespace prefix. A write to one data type can silently overwrite the other, corrupting contract state.

## Exploit Scenario

1. Contract stores `Balance(alice)` and `Allowance(alice)` using the same raw key.
2. A balance update overwrites the allowance entry (or vice versa).
3. Alice's allowance is corrupted; a spender can drain more than permitted.

## Vulnerable Code

```rust
// ❌ Both use the same key derivation
env.storage().persistent().set(&account, &balance);
env.storage().persistent().set(&account, &allowance);
```

## Secure Fix

```rust
// ✅ Namespaced enum variants
env.storage().persistent().set(&DataKey::Balance(account.clone()), &balance);
env.storage().persistent().set(&DataKey::Allowance(account.clone()), &allowance);
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
