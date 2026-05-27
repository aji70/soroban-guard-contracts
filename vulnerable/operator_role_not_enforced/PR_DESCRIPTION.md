# feat: Add vulnerable contract - operator role is read but never enforced

Implements the operator role vulnerability described in [issue #222](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/issues/222).

A maintenance contract that stores an operator address for privileged actions, but the protected function reads the role and continues execution even when the caller is not the operator. This makes the role storage decorative and exposes privileged actions to any caller.

## Vulnerable pattern

```rust
pub fn emergency_withdraw(env: Env, caller: Address, amount: i128) {
    caller.require_auth();

    // ❌ Role lookup result is ignored — no assertion that caller == operator.
    let _operator: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Operator)
        .expect("not initialized");

    // Privileged state change proceeds without role enforcement.
    let balance: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::Balance)
        .unwrap_or(0);
    assert!(balance >= amount, "insufficient balance");
    env.storage()
        .persistent()
        .set(&DataKey::Balance, &(balance - amount));
}
```

## Secure fix

```rust
pub fn emergency_withdraw(env: Env, caller: Address, amount: i128) {
    caller.require_auth();

    let operator: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Operator)
        .expect("not initialized");

    // ✅ Enforce the role check.
    assert!(caller == operator, "caller is not the operator");

    // Privileged state change only proceeds if caller is the operator.
    let balance: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::Balance)
        .unwrap_or(0);
    assert!(balance >= amount, "insufficient balance");
    env.storage()
        .persistent()
        .set(&DataKey::Balance, &(balance - amount));
}
```

## What's added

- `VulnerableVault` — stores operator role but `emergency_withdraw` reads it and continues without enforcement
- `secure::SecureVault` — asserts `caller == operator` before executing privileged state changes

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_non_operator_can_drain_vault` | Vulnerable | non-operator calls `emergency_withdraw` and succeeds |
| `test_operator_can_withdraw` | Vulnerable | operator can also withdraw (expected) |
| `test_secure_operator_can_withdraw` | Secure | operator succeeds |
| `test_secure_non_operator_rejected` | Secure | panics with `caller is not the operator` |

**Severity:** High

Closes #222
