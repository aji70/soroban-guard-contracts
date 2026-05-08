# `vulnerable/unprotected_mint`

## Vulnerability: Unprotected Mint Function

**Severity:** Critical

## Description

The `mint` function is callable by any address without admin authorisation. An attacker can mint an unlimited number of tokens to any address, inflating the supply and devaluing all existing token holders.

## Exploit Scenario

1. Attacker calls `mint(attacker, u64::MAX)`.
2. Contract mints tokens without checking the caller is the admin.
3. Attacker holds the entire token supply; all other holders are diluted to near zero.

## Vulnerable Code

```rust
pub fn mint(env: Env, to: Address, amount: i128) {
    // ❌ Missing: require_admin(&env);
    let balance = get_balance(&env, &to);
    set_balance(&env, &to, balance + amount);
}
```

## Secure Fix

```rust
pub fn mint(env: Env, to: Address, amount: i128) {
    require_admin(&env); // ✅
    let balance = get_balance(&env, &to);
    set_balance(&env, &to, balance + amount);
}
```

No separate secure crate — the fix is an inline admin auth check.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
