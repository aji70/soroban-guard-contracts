# `vulnerable/missing_events`

## Vulnerability: No Events Emitted

**Severity:** Low

## Description

The contract mutates state (transfers, admin changes, etc.) without emitting any events. Off-chain indexers, dashboards, and audit tools are blind to these state changes, making it impossible to detect suspicious activity or reconstruct history.

## Exploit Scenario

1. Attacker exploits another vulnerability (e.g. missing auth) to drain funds.
2. No events are emitted; the exploit is invisible to monitoring systems.
3. The attack goes undetected until a user notices their balance is zero.

## Vulnerable Code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    do_transfer(&env, &from, &to, amount);
    // ❌ Missing: env.events().publish(...)
}
```

## Secure Fix

```rust
do_transfer(&env, &from, &to, amount);
env.events().publish((symbol_short!("transfer"),), (from, to, amount)); // ✅
```

No separate secure crate — the fix is adding event emissions to each state-mutating function.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
