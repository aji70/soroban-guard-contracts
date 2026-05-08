# `vulnerable/allowance_not_decremented`

## Vulnerability: Allowance Not Decremented After Spend

**Severity:** High

## Description

After a `transfer_from` spends an allowance, the contract does not reduce the stored allowance. The spender can call `transfer_from` repeatedly, draining the owner's balance far beyond the approved amount.

## Exploit Scenario

1. Alice approves Bob for 100 tokens.
2. Bob calls `transfer_from(alice, bob, 100)` — succeeds.
3. Bob calls `transfer_from(alice, bob, 100)` again — still succeeds because the allowance was never decremented.
4. Bob drains Alice's entire balance.

## Vulnerable Code

```rust
pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
    spender.require_auth();
    let allowance = get_allowance(&env, &from, &spender);
    assert!(allowance >= amount, "insufficient allowance");
    // ❌ Missing: set_allowance(&env, &from, &spender, allowance - amount);
    do_transfer(&env, &from, &to, amount);
}
```

## Secure Fix

```rust
set_allowance(&env, &from, &spender, allowance - amount); // ✅
do_transfer(&env, &from, &to, amount);
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
