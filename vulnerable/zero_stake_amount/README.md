# vulnerable/zero_stake_amount

**Severity:** Medium

## Description

The `stake` function accepts any `i128` value including zero and negative numbers without validation. This allows callers to:

- **Zero stake** — creates a persistent storage entry and emits an event without transferring any tokens, polluting ledger state and wasting resources.
- **Negative stake** — silently underflows the staker's recorded balance, corrupting accounting.

## Vulnerable Pattern

```rust
pub fn stake(env: Env, staker: Address, amount: i128) {
    staker.require_auth();
    // BUG: amount is never validated — zero and negative values accepted
    let current: i128 = env.storage().persistent().get(&staker).unwrap_or(0);
    env.storage().persistent().set(&staker, &(current + amount));
}
```

## Fix

Add a guard at the top of `stake` before any state mutation:

```rust
pub fn stake(env: Env, staker: Address, amount: i128) {
    staker.require_auth();
    // FIX: reject zero and negative amounts
    if amount <= 0 {
        panic!("amount must be positive");
    }
    let current: i128 = env.storage().persistent().get(&staker).unwrap_or(0);
    env.storage().persistent().set(&staker, &(current + amount));
}
```

The secure implementation lives in [`src/secure.rs`](src/secure.rs).
