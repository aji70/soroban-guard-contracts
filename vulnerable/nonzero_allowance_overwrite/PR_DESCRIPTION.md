# PR: Add Vulnerable Contract - Nonzero Allowance Overwrite

## Summary

Implements a new vulnerable Soroban token contract demonstrating the **nonzero allowance overwrite** vulnerability, where `approve()` overwrites an existing nonzero allowance without requiring it to be reset first. This enables a race condition where a spender can use both the old and new allowances.

## Files Added

- `vulnerable/nonzero_allowance_overwrite/Cargo.toml` — Package manifest
- `vulnerable/nonzero_allowance_overwrite/src/lib.rs` — Vulnerable implementation with tests
- `vulnerable/nonzero_allowance_overwrite/src/secure.rs` — Secure implementation with tests
- `vulnerable/nonzero_allowance_overwrite/README.md` — Vulnerability explanation and fix
- Updated `Cargo.toml` workspace members list

## Vulnerability Details

### Vulnerable Pattern

```rust
pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
    owner.require_auth();
    // ❌ No check that current allowance is zero
    set_allowance(&env, &owner, &spender, amount);
}
```

### Attack Scenario

1. Owner approves spender for 100 tokens
2. Owner wants to increase to 200 (grant more)
3. Owner calls `approve(spender, 200)` — overwrites 100 → 200
4. Spender observes old allowance (100) and submits transfer tx
5. Owner's approve tx executes, setting allowance to 200
6. Spender's transfer tx executes, using 100
7. Spender then uses the new 200 allowance
8. **Result**: Spender used 300 total instead of 200

## Secure Fix

Require allowance to be zero before setting a new nonzero value:

```rust
pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
    owner.require_auth();
    if amount != 0 {
        let current = get_allowance(&env, &owner, &spender);
        assert!(current == 0, "nonzero allowance: must reset to zero first");
    }
    set_allowance(&env, &owner, &spender, amount);
}
```

## Tests

### Vulnerable Implementation Tests

- `test_initial_approve` — Initial approval succeeds
- `test_partial_transfer_from` — Spender uses partial allowance
- `test_race_condition_overwrite_allowance` — Demonstrates race when reducing allowance
- `test_race_condition_increase_allowance` — Demonstrates race when increasing allowance

### Secure Implementation Tests

- `test_initial_approve` — Initial approval succeeds
- `test_partial_transfer_from` — Spender uses partial allowance
- `test_overwrite_nonzero_allowance_rejected` — ✅ Rejects nonzero overwrite
- `test_reset_then_approve_succeeds` — ✅ Must reset to zero first
- `test_revoke_allowance` — ✅ Can revoke (set to zero) at any time

## Severity

**Medium** — Requires specific conditions (owner attempting to change allowance while spender is active) but enables significant value extraction through race conditions.

## References

- [ERC-20 Approve Race Condition](https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729)
- [OpenZeppelin increaseAllowance/decreaseAllowance](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-)
