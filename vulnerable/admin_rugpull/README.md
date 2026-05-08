# `vulnerable/admin_rugpull`

## Vulnerability: Admin Rug-Pull (Single-Step Admin Transfer)

**Severity:** High

## Description

`set_admin()` immediately replaces the admin in a single transaction. There is no confirmation step from the new admin. A compromised or malicious admin can transfer control to an attacker-controlled address instantly, with no recovery window.

## Exploit Scenario

1. Admin key is compromised.
2. Attacker calls `set_admin(attacker_address)` in one transaction.
3. Attacker immediately controls all privileged functions; original admin has no recourse.

## Vulnerable Code

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    require_admin(&env);
    // ❌ Immediate transfer — no acceptance step
    env.storage().persistent().set(&DataKey::Admin, &new_admin);
}
```

## Secure Fix

```rust
// Two-step: propose then accept
pub fn propose_admin(env: Env, new_admin: Address) {
    require_admin(&env);
    env.storage().persistent().set(&DataKey::PendingAdmin, &new_admin); // ✅
}
pub fn accept_admin(env: Env) {
    let pending: Address = env.storage().persistent().get(&DataKey::PendingAdmin).unwrap();
    pending.require_auth(); // ✅ new admin must sign
    env.storage().persistent().set(&DataKey::Admin, &pending);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
