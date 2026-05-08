# `vulnerable/zero_admin`

## Vulnerability: Zero Address Admin

**Severity:** High

## Description

The contract allows the admin to be set to the zero address (all-zero bytes). If this happens, all admin-gated functions become permanently inaccessible because no one can sign as the zero address, effectively bricking the contract.

## Exploit Scenario

1. Admin accidentally or maliciously calls `set_admin(zero_address)`.
2. The zero address is stored as admin.
3. All admin functions (`upgrade`, `add_scanner`, etc.) are permanently locked.

## Vulnerable Code

```rust
pub fn initialize(env: Env, admin: Address) {
    // ❌ Missing: assert!(admin != zero_address, "admin cannot be zero address");
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

## Secure Fix

Validate the admin address is not the zero address at initialisation and in `set_admin`. On Soroban, use a sentinel check appropriate for the `Address` type.

No separate secure crate — the fix is an inline guard.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
