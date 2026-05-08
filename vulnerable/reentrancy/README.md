# `vulnerable/reentrancy`

## Vulnerability: Re-Entrancy

**Severity:** Critical

## Description

The contract makes an external call (e.g. token transfer) before updating its own state. If the external contract calls back into the vulnerable contract before the state update, it can exploit the stale state — for example, withdrawing the same funds twice.

## Exploit Scenario

1. Attacker calls `withdraw(100)`.
2. Contract sends 100 tokens to the attacker's contract via an external call.
3. Attacker's contract immediately calls `withdraw(100)` again.
4. The vulnerable contract's balance has not been updated yet; the second withdrawal succeeds.
5. Attacker receives 200 tokens for a 100-token balance.

## Vulnerable Code

```rust
pub fn withdraw(env: Env, account: Address, amount: i128) {
    account.require_auth();
    let balance = get_balance(&env, &account);
    assert!(balance >= amount, "insufficient balance");
    token_client.transfer(&env.current_contract_address(), &account, &amount); // ❌ external call first
    set_balance(&env, &account, balance - amount); // state updated after
}
```

## Secure Fix

Apply checks-effects-interactions: update state before making external calls.

```rust
set_balance(&env, &account, balance - amount); // ✅ state first
token_client.transfer(&env.current_contract_address(), &account, &amount);
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
