# `vulnerable/flash_loan_no_check`

## Vulnerability: Flash Loan Without Repayment Check

**Severity:** Critical

## Description

The flash loan function transfers tokens to the borrower but does not verify repayment before returning. An attacker can borrow the entire pool and never repay, draining the contract.

## Exploit Scenario

1. Attacker calls `flash_loan(attacker, pool_balance)`.
2. Contract transfers tokens to attacker.
3. Attacker does not repay; contract returns without checking the balance was restored.
4. Attacker keeps the tokens.

## Vulnerable Code

```rust
pub fn flash_loan(env: Env, borrower: Address, amount: i128) {
    transfer_out(&env, &borrower, amount);
    // ❌ Missing repayment check
}
```

## Secure Fix

```rust
pub fn flash_loan(env: Env, borrower: Address, amount: i128) {
    let balance_before = get_pool_balance(&env);
    transfer_out(&env, &borrower, amount);
    // borrower executes their logic here (via callback or same tx)
    let balance_after = get_pool_balance(&env);
    assert!(balance_after >= balance_before, "flash loan not repaid"); // ✅
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
