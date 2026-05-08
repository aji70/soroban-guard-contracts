# `vulnerable/no_slippage`

## Vulnerability: Missing Slippage Guard

**Severity:** High

## Description

The swap function executes without a minimum output (`min_out`) parameter. A front-runner or sandwich attacker can manipulate the pool price between the user's transaction submission and execution, causing the user to receive far less than expected.

## Exploit Scenario

1. User submits a swap for token A → token B.
2. Attacker front-runs with a large buy of token B, moving the price.
3. User's swap executes at the worse price; attacker back-runs to profit.
4. User receives significantly less than the quoted amount.

## Vulnerable Code

```rust
pub fn swap(env: Env, amount_in: i128) -> i128 {
    // ❌ No min_out check
    let amount_out = calculate_out(&env, amount_in);
    execute_swap(&env, amount_in, amount_out);
    amount_out
}
```

## Secure Fix

```rust
pub fn swap(env: Env, amount_in: i128, min_out: i128) -> i128 {
    let amount_out = calculate_out(&env, amount_in);
    assert!(amount_out >= min_out, "slippage exceeded"); // ✅
    execute_swap(&env, amount_in, amount_out);
    amount_out
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
