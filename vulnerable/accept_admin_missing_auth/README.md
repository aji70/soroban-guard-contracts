# `vulnerable/accept_admin_missing_auth`

## Vulnerability: Missing `require_auth` in `accept_admin`

**Severity:** Critical

## Description

A two-step admin transfer contract where `accept_admin()` reads the pending admin from storage and writes them as the new admin — but **never calls `pending.require_auth()`**. Any address can call `accept_admin()` and seize control of the contract.

## Exploit Scenario

1. Admin proposes a new admin via `propose_admin(new_admin)`.
2. Before the intended pending admin can accept, a random attacker calls `accept_admin()`.
3. The attacker takes over as admin — the intended target never signed or authorised the transfer.

## Vulnerable Code

```rust
pub fn accept_admin(env: Env) {
    let pending: Address = env.storage().persistent().get(&DataKey::PendingAdmin).expect("no pending admin");
    // ❌ Missing: pending.require_auth();
    env.storage().persistent().set(&DataKey::Admin, &pending);
    env.storage().persistent().remove(&DataKey::PendingAdmin);
}
```

## Secure Fix

```rust
pub fn accept_admin(env: Env) {
    let pending: Address = env.storage().persistent().get(&SecureDataKey::PendingAdmin).expect("no pending admin");
    // ✅ Require the pending admin to authorise the transfer.
    pending.require_auth();
    env.storage().persistent().set(&SecureDataKey::Admin, &pending);
    env.storage().persistent().remove(&SecureDataKey::PendingAdmin);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
