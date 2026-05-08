# `vulnerable/unprotected_burn`

## Vulnerability: Unprotected Burn Function

**Severity:** Critical

## Description

The `burn` function destroys tokens from any account without requiring authorisation from the account owner. Any caller can burn another user's tokens, destroying their funds.

## Exploit Scenario

1. Attacker calls `burn(victim, victim_balance)`.
2. Contract burns the victim's tokens without checking the caller is the victim.
3. Victim's entire balance is destroyed.

## Vulnerable Code

```rust
pub fn burn(env: Env, account: Address, amount: i128) {
    // ❌ Missing: account.require_auth();
    let balance = get_balance(&env, &account);
    set_balance(&env, &account, balance - amount);
}
```

## Secure Fix

```rust
pub fn burn(env: Env, account: Address, amount: i128) {
    account.require_auth(); // ✅
    let balance = get_balance(&env, &account);
    set_balance(&env, &account, balance.checked_sub(amount).unwrap());
}
```

See [`secure/secure_burn`](../../secure/secure_burn) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
