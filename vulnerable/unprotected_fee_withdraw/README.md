# `vulnerable/unprotected_fee_withdraw`

## Vulnerability: Unprotected Fee Withdrawal

**Severity:** Critical

## Description

The fee withdrawal function transfers accumulated fees to an arbitrary recipient without verifying the caller is the admin. Any address can drain the contract's fee balance to themselves.

## Exploit Scenario

1. Contract accumulates swap fees over time.
2. Attacker calls `withdraw_fees(attacker)`.
3. Contract transfers all fees to the attacker without an admin check.
4. Legitimate fee recipients (protocol treasury) receive nothing.

## Vulnerable Code

```rust
pub fn withdraw_fees(env: Env, recipient: Address) {
    // ❌ Missing: require_admin(&env);
    let fees = get_fees(&env);
    set_fees(&env, 0);
    token_client.transfer(&env.current_contract_address(), &recipient, &fees);
}
```

## Secure Fix

```rust
pub fn withdraw_fees(env: Env, recipient: Address) {
    require_admin(&env); // ✅
    let fees = get_fees(&env);
    set_fees(&env, 0);
    token_client.transfer(&env.current_contract_address(), &recipient, &fees);
}
```

See [`secure/protected_fee_withdraw`](../../secure/protected_fee_withdraw) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
