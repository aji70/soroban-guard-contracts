# `vulnerable/negative_transfer`

## Vulnerability: Negative Amount Transfer

**Severity:** High

## Description

The transfer function accepts negative `amount` values. Transferring a negative amount effectively moves tokens in the reverse direction, allowing an attacker to inflate their own balance by "sending" a negative amount to themselves or others.

## Exploit Scenario

1. Attacker calls `transfer(attacker, victim, -1_000_000)`.
2. Contract subtracts `-1_000_000` from the attacker's balance (adding 1M) and adds `-1_000_000` to the victim's balance (subtracting 1M).
3. Attacker gains tokens; victim loses tokens.

## Vulnerable Code

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    from.require_auth();
    // ❌ Missing: assert!(amount > 0, "amount must be positive");
    set_balance(&env, &from, get_balance(&env, &from) - amount);
    set_balance(&env, &to, get_balance(&env, &to) + amount);
}
```

## Secure Fix

```rust
assert!(amount > 0, "amount must be positive"); // ✅
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
