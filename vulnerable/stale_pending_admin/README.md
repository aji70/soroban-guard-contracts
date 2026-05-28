# `vulnerable/stale_pending_admin`

## Vulnerability: Stale Pending Admin (Cancellation Does Not Clear Storage)

**Severity:** High

## Description

A two-step admin transfer contract where `cancel_admin_transfer()` only emits an event but never removes the `PendingAdmin` from persistent storage. The previously proposed address can still call `accept_admin()` and take over ownership after cancellation.

## Exploit Scenario

1. Admin proposes a new admin via `propose_admin(new_admin)`.
2. Admin changes their mind and calls `cancel_admin_transfer()`.
3. The proposed address calls `accept_admin()` and takes over ownership — even though the transfer was cancelled.

## Vulnerable Code

```rust
pub fn cancel_admin_transfer(env: Env) {
    let current: Address = env.storage().persistent().get(&DataKey::Admin).expect("not initialized");
    current.require_auth();
    // ❌ Missing: env.storage().persistent().remove(&DataKey::PendingAdmin);
    env.events().publish((symbol_short!("cancel"),), (current,));
}
```

## Secure Fix

```rust
pub fn cancel_admin_transfer(env: Env) {
    let current: Address = env.storage().persistent().get(&SecureDataKey::Admin).expect("not initialized");
    current.require_auth();
    // ✅ Actually remove the pending admin — cancellation is real.
    env.storage().persistent().remove(&SecureDataKey::PendingAdmin);
    env.events().publish((symbol_short!("cancel"),), (current,));
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
