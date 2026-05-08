# `vulnerable/unprotected_admin`

## Vulnerability: Privilege Escalation (Unprotected Admin Functions)

**Severity:** Critical

## Description

`set_admin()` and `upgrade()` are callable by any address. An attacker can replace the admin with their own address or upgrade the contract WASM to malicious code, taking full control of the contract.

## Exploit Scenario

1. Attacker calls `set_admin(attacker_address)`.
2. Contract stores the new admin without verifying the caller is the current admin.
3. Attacker now controls all privileged functions including `upgrade()`.

## Vulnerable Code

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    // ❌ Missing: require_admin(&env);
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

## Secure Fix

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    require_admin(&env); // ✅
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

See [`secure/protected_admin`](../../secure/protected_admin) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
