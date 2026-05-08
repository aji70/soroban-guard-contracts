# `vulnerable/zero_deposit`

## Vulnerability: Zero-Value Deposit

**Severity:** Medium

## Description

The deposit function accepts `amount = 0` without rejecting it. An attacker can create storage entries at zero cost, wasting ledger space and potentially triggering edge cases in downstream logic that assumes deposits are positive.

## Exploit Scenario

1. Attacker calls `deposit(attacker, 0)` thousands of times.
2. Each call writes a storage entry, consuming ledger resources.
3. Legitimate users pay higher fees due to inflated state size.

## Vulnerable Code

```rust
pub fn deposit(env: Env, account: Address, amount: i128) {
    account.require_auth();
    // ❌ Missing: assert!(amount > 0, "amount must be positive");
    let balance = get_balance(&env, &account);
    set_balance(&env, &account, balance + amount);
}
```

## Secure Fix

```rust
pub fn deposit(env: Env, account: Address, amount: i128) {
    account.require_auth();
    assert!(amount > 0, "amount must be positive"); // ✅
    // ...
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
