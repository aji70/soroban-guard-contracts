# `vulnerable/silent_admin_change`

## Vulnerability: Silent Admin Change — No Event on Privilege Escalation

**Severity:** Medium

## Description

The `set_admin` function updates the admin address in persistent storage but never calls `env.events().publish()`. Off-chain monitors, dashboards, and audit tools have no way to detect admin changes without polling storage on every ledger. A malicious or compromised admin can silently transfer control to an attacker-controlled address with no on-chain trace.

## Exploit Scenario

1. Compromised admin calls `set_admin(attacker_address)`.
2. Contract updates storage with no event emitted.
3. Attacker now controls the contract — no on-chain trace exists for monitors or auditors to detect.

## Vulnerable Code

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    let current: Address = env.storage().persistent().get(&"admin").unwrap();
    current.require_auth();
    // ❌ BUG: no event emitted — admin change is invisible to off-chain monitors
    env.storage().persistent().set(&"admin", &new_admin);
}
```

## Secure Fix

```rust
pub fn set_admin(env: Env, new_admin: Address) {
    let old_admin: Address = env.storage().persistent().get(&"admin").unwrap();
    old_admin.require_auth();

    env.storage().persistent().set(&"admin", &new_admin);

    // ✅ Emit event so off-chain monitors can detect the change
    env.events().publish(
        (symbol_short!("AdminChg"),),
        (old_admin, new_admin),
    );
}
```

## Event Schema

| Field    | Type      | Description                        |
|----------|-----------|------------------------------------|
| topic[0] | `Symbol`  | `"AdminChg"` — event identifier    |
| data[0]  | `Address` | Previous admin address             |
| data[1]  | `Address` | New admin address                  |

Published via: `env.events().publish((symbol_short!("AdminChg"),), (old_admin, new_admin))`

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
