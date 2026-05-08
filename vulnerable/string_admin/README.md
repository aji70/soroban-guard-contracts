# `vulnerable/string_admin`

## Vulnerability: String-Typed Admin

**Severity:** High

## Description

The admin is stored as a `String` instead of an `Address`. String comparison is case-sensitive and error-prone; it bypasses Soroban's built-in auth system (`require_auth`), making it trivial to spoof the admin by passing a matching string without actually controlling the corresponding key.

## Exploit Scenario

1. Admin is stored as `"GADMIN123..."` (a string).
2. Attacker calls `admin_action("GADMIN123...")` — the string matches.
3. No cryptographic proof is required; the attacker gains admin access.

## Vulnerable Code

```rust
pub fn set_admin(env: Env, caller: String, new_admin: String) {
    let admin: String = env.storage().persistent().get(&DataKey::Admin).unwrap();
    assert!(caller == admin, "not admin"); // ❌ string comparison, no crypto
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

## Secure Fix

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    require_admin(&env); // ✅ uses Address + require_auth()
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
