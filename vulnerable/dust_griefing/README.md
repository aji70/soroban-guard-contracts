# `vulnerable/dust_griefing`

## Vulnerability: Dust Griefing

**Severity:** Medium

## Description

The contract accepts deposits of any positive amount, including dust (e.g. 1 stroop). An attacker can flood the contract with tiny deposits from many addresses, bloating persistent storage and raising costs for all users.

## Exploit Scenario

1. Attacker creates thousands of accounts and calls `deposit(account_n, 1)` from each.
2. Each call creates a new persistent storage entry.
3. Storage rent costs rise; legitimate users pay more to interact with the contract.

## Vulnerable Code

```rust
pub fn deposit(env: Env, account: Address, amount: i128) {
    account.require_auth();
    // ❌ No minimum deposit threshold
    set_balance(&env, &account, get_balance(&env, &account) + amount);
}
```

## Secure Fix

```rust
const MIN_DEPOSIT: i128 = 10_000_000; // 1 XLM in stroops

pub fn deposit(env: Env, account: Address, amount: i128) {
    account.require_auth();
    assert!(amount >= MIN_DEPOSIT, "deposit below minimum"); // ✅
    // ...
}
```

See [`secure/dust_griefing`](../../secure/dust_griefing) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
