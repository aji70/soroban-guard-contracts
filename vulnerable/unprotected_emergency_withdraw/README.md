# `vulnerable/unprotected_emergency_withdraw`

## Vulnerability: Unprotected Emergency Withdraw

**Severity:** Critical

## Description

An emergency withdrawal function intended for admin use only is callable by any address. An attacker can drain the entire contract balance at any time by invoking the emergency exit.

## Exploit Scenario

1. Attacker calls `emergency_withdraw(attacker)`.
2. Contract transfers all funds to the attacker without checking the caller is the admin.
3. Contract is drained instantly.

## Vulnerable Code

```rust
pub fn emergency_withdraw(env: Env, recipient: Address) {
    // ❌ Missing: require_admin(&env);
    let balance = get_pool_balance(&env);
    token_client.transfer(&env.current_contract_address(), &recipient, &balance);
}
```

## Secure Fix

```rust
pub fn emergency_withdraw(env: Env, recipient: Address) {
    require_admin(&env); // ✅
    // optionally also enforce a time-lock before allowing withdrawal
    let balance = get_pool_balance(&env);
    token_client.transfer(&env.current_contract_address(), &recipient, &balance);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
