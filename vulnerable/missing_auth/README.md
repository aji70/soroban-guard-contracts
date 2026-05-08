# `vulnerable/missing_auth`

## Vulnerability: Missing Authorisation

**Severity:** Critical

## Description

The `transfer()` function mutates token balances without calling `require_auth()` on the sender. Any account can move tokens out of any other account's balance without their consent.

## Exploit Scenario

1. Attacker calls `transfer(victim, attacker, 1_000_000)`.
2. Contract updates balances without verifying the victim signed the transaction.
3. Attacker drains the victim's entire balance.

## Vulnerable Code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    // ❌ Missing: from.require_auth();
    let from_balance = get_balance(&env, &from);
    set_balance(&env, &from, from_balance - amount);
    // ...
}
```

## Secure Fix

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth(); // ✅
    // ...
}
```

See [`secure/secure_vault`](../../secure/secure_vault) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
