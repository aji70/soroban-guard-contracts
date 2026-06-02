# Nonzero Allowance Overwrite

## Vulnerability

The `approve()` function overwrites the allowance without requiring it to be zero first. This enables a race condition where a spender can use both the old and new allowances.

### Attack Scenario

1. Owner approves spender for 100 tokens
2. Owner wants to increase allowance to 200 (grant more)
3. Owner calls `approve(spender, 200)` — overwrites 100 → 200
4. Spender observes the old allowance (100) and submits a transfer tx
5. Owner's approve tx executes, setting allowance to 200
6. Spender's transfer tx executes, using 100
7. Spender then uses the new 200 allowance
8. **Result**: Spender used 300 total instead of 200

### Root Cause

```rust
pub fn approve(env: Env, owner: Address, spender: Address, amount: i128) {
    owner.require_auth();
    // ❌ No check that current allowance is zero
    set_allowance(&env, &owner, &spender, amount);
}
```

## Secure Fix

Require the allowance to be zero before setting a new nonzero value:

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

This forces the owner to explicitly reset the allowance to zero before granting a new nonzero value, eliminating the race condition.

## Alternative: Increase/Decrease Helpers

Some implementations provide `increase_allowance()` and `decrease_allowance()` functions instead:

```rust
pub fn increase_allowance(env: Env, owner: Address, spender: Address, delta: i128) {
    owner.require_auth();
    let current = get_allowance(&env, &owner, &spender);
    set_allowance(&env, &owner, &spender, current + delta);
}

pub fn decrease_allowance(env: Env, owner: Address, spender: Address, delta: i128) {
    owner.require_auth();
    let current = get_allowance(&env, &owner, &spender);
    assert!(current >= delta, "insufficient allowance to decrease");
    set_allowance(&env, &owner, &spender, current - delta);
}
```

This avoids the race by using atomic delta operations instead of overwrites.

## References

- [ERC-20 Approve Race Condition](https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729)
- [OpenZeppelin increaseAllowance/decreaseAllowance](https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20-increaseAllowance-address-uint256-)
