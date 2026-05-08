# `vulnerable/underflow_transfer`

## Vulnerability: Integer Underflow

**Severity:** High

## Description

The transfer function subtracts the amount from the sender's balance using unchecked arithmetic. If the sender's balance is less than the amount, the subtraction wraps around to a very large positive number, giving the sender an enormous balance.

## Exploit Scenario

1. Attacker has a balance of 0.
2. Attacker calls `transfer(attacker, victim, 1)`.
3. `0 - 1` wraps to `u64::MAX` (or `i128::MAX` depending on type).
4. Attacker now has an astronomically large balance.

## Vulnerable Code

```rust
let new_balance = from_balance - amount; // ❌ wraps on underflow
set_balance(&env, &from, new_balance);
```

## Secure Fix

```rust
let new_balance = from_balance
    .checked_sub(amount)
    .expect("insufficient balance"); // ✅
assert!(new_balance >= 0, "insufficient balance");
```

No separate secure crate — see [`secure/secure_vault`](../../secure/secure_vault) for the pattern.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
