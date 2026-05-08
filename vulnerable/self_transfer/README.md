# `vulnerable/self_transfer`

## Vulnerability: Self-Transfer

**Severity:** Medium

## Description

The transfer function allows `from == to`. A self-transfer can corrupt balance accounting if the implementation reads the balance before both writes, effectively doubling the balance or causing other unexpected state.

## Exploit Scenario

1. Attacker calls `transfer(attacker, attacker, balance)`.
2. Contract reads `from_balance`, subtracts amount, then reads `to_balance` (same slot, now reduced), and adds amount — net result may be incorrect depending on read order.
3. Attacker's balance is corrupted in their favour.

## Vulnerable Code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ Missing: assert!(from != to, "self-transfer not allowed");
    let from_bal = get_balance(&env, &from);
    let to_bal = get_balance(&env, &to);
    set_balance(&env, &from, from_bal - amount);
    set_balance(&env, &to, to_bal + amount);
}
```

## Secure Fix

```rust
assert!(from != to, "self-transfer not allowed"); // ✅
```

No separate secure crate — the fix is an inline guard.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
