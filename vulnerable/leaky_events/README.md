# `vulnerable/leaky_events`

## Vulnerability: Sensitive Data in Events

**Severity:** Medium

## Description

The contract emits private data (e.g. private keys, passwords, or PII) in contract events. Soroban events are publicly visible on-chain and to any indexer, so sensitive data is permanently exposed.

## Exploit Scenario

1. Contract emits an event containing a user's private key or secret.
2. Any on-chain observer or indexer reads the event data.
3. Attacker uses the leaked secret to compromise the user's account.

## Vulnerable Code

```rust
env.events().publish(
    (symbol_short!("register"),),
    (account.clone(), private_key, password), // ❌ sensitive fields
);
```

## Secure Fix

```rust
env.events().publish(
    (symbol_short!("register"),),
    (account.clone(),), // ✅ emit only non-sensitive identifier
);
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
