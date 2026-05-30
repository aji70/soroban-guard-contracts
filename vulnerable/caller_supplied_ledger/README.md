# `vulnerable/caller_supplied_ledger`

## Vulnerability: Caller-Supplied Ledger Context

**Severity:** Critical

## Description

A time-sensitive vesting/lock contract accepts a `current_ledger` argument from the caller instead of reading the ledger sequence from `env.ledger()`. Attackers can bypass lock periods, cliff checks, and vesting schedules by supplying an arbitrarily large ledger sequence, draining funds before the intended unlock.

## Exploit Scenario

1. Alice deposits 5000 tokens with a 1000-ledger lock period and 100-ledger cliff.
2. Bob (attacker) calls `withdraw` with `current_ledger = 1100` (far in the future) while the real ledger is only at 150.
3. The contract trusts the caller-supplied ledger, computes 100% vesting, and releases all 5000 tokens to Bob.
4. Bob drains the vault before the lock period expires.

## Vulnerable Code

```rust
// see src/lib.rs
pub fn withdraw(env: Env, user: Address, amount: i128, current_ledger: u32) {
    // ...
    // ❌ BUG: Uses caller-supplied `current_ledger` instead of `env.ledger().sequence()`.
    if current_ledger < deposit_ledger + cliff_duration {
        panic!("still in cliff period");
    }
    let elapsed = current_ledger - deposit_ledger;
    // ...
}
```

## Secure Fix

```rust
// corrected version
pub fn withdraw(env: Env, user: Address, amount: i128) {
    // ...
    // ✅ SECURE: Read ledger sequence from the environment — cannot be spoofed.
    let current_ledger = env.ledger().sequence();
    if current_ledger < deposit_ledger + cliff_duration {
        panic!("still in cliff period");
    }
    // ...
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
