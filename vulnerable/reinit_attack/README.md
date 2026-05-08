# `vulnerable/reinit_attack`

## Vulnerability: Re-Initialisation Attack

**Severity:** Critical

## Description

The `initialize` function does not check whether the contract has already been initialised. An attacker can call it again to replace the admin, reset parameters, or wipe state, taking full control of the contract.

## Exploit Scenario

1. Contract is deployed and initialised by the legitimate admin.
2. Attacker calls `initialize(attacker_address)`.
3. Contract overwrites the admin with the attacker's address.
4. Attacker controls all privileged functions.

## Vulnerable Code

```rust
pub fn initialize(env: Env, admin: Address) {
    // ❌ Missing: assert!(!env.storage().persistent().has(&DataKey::Admin), "already initialized");
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

## Secure Fix

```rust
pub fn initialize(env: Env, admin: Address) {
    assert!(
        !env.storage().persistent().has(&DataKey::Admin),
        "already initialized" // ✅
    );
    env.storage().persistent().set(&DataKey::Admin, &admin);
}
```

No separate secure crate — the fix is an inline guard.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
