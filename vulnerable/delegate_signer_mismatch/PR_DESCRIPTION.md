# feat: Add vulnerable contract - delegate signer mismatch allows unauthorized delegated transfer

Implements the delegate signer mismatch vulnerability described in [issue #221](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/issues/221).

A token-like contract that accepts a `delegate` address parameter for delegated transfers but calls `owner.require_auth()` instead of `delegate.require_auth()`. This allows a malicious caller to consume another delegate's allowance because the signer and allowance spender are not bound together.

## Vulnerable pattern

```rust
pub fn transfer_from(
    env: Env,
    delegate: Address,
    owner: Address,
    to: Address,
    amount: i128,
) -> i128 {
    // ❌ Wrong signer — should be delegate.require_auth()
    owner.require_auth();

    let allowance = get_allowance(&env, &owner, &delegate);
    assert!(allowance >= amount, "insufficient allowance");

    // Transfer proceeds using delegate's allowance but owner's signature
    // ...
}
```

## Secure fix

```rust
pub fn transfer_from(
    env: Env,
    delegate: Address,
    owner: Address,
    to: Address,
    amount: i128,
) -> i128 {
    // ✅ Correct signer — delegate must authorize
    delegate.require_auth();

    let allowance = get_allowance(&env, &owner, &delegate);
    assert!(allowance >= amount, "insufficient allowance");

    // Transfer proceeds only if the actual delegate signed
    // ...
}
```

## What's added

- `VulnerableToken` — `transfer_from` accepts `delegate` parameter but authorizes `owner`, allowing any delegate with any allowance from that owner to consume any other delegate's allowance
- `secure::SecureToken` — calls `delegate.require_auth()` to bind the signer to the allowance being consumed

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_attacker_delegate_can_spend_other_allowance` | Vulnerable | attacker delegate consumes legitimate delegate's 300 allowance using owner's signature |
| `test_legitimate_delegate_can_spend` | Vulnerable | legitimate delegate can also spend (expected) |
| `test_secure_legitimate_delegate_can_spend` | Secure | legitimate delegate succeeds |
| `test_secure_attacker_delegate_rejected` | Secure | panics when attacker tries to use another delegate's allowance |

**Severity:** Critical

Closes #221
