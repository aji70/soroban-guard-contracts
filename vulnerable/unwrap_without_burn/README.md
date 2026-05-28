# Unwrap Without Burn

## Vulnerability

A wrapper token contract that releases underlying tokens during unwrap but forgets to burn wrapper shares. Users can repeatedly unwrap the same shares and drain the custody contract.

## Severity

**Critical**

## Description

The vulnerable contract implements a token wrapper that allows users to:
1. **Wrap**: Deposit underlying tokens and receive wrapper shares
2. **Unwrap**: Redeem wrapper shares for underlying tokens

However, the `unwrap` function has a critical flaw: it transfers underlying tokens to the user but **does not burn or decrement the wrapper token balance**. This allows users to call unwrap multiple times with the same wrapper shares, draining all underlying tokens from custody.

## Vulnerable Code

```rust
pub fn unwrap(env: Env, user: Address, amount: i128) {
    user.require_auth();

    // Check user has enough wrapper balance
    let current_balance: i128 = env
        .storage()
        .persistent()
        .get(&balance_key)
        .unwrap_or(0);

    if current_balance < amount {
        panic!("insufficient wrapper balance");
    }

    // ❌ Transfer underlying tokens WITHOUT burning wrapper shares
    let token_client = token::TokenClient::new(&env, &underlying_token);
    token_client.transfer(&env.current_contract_address(), &user, &amount);

    // Update custody balance
    env.storage()
        .persistent()
        .set(&DataKey::CustodyBalance, &(custody - amount));

    // ❌ MISSING: Burn wrapper shares
    // env.storage().persistent().set(&balance_key, &(current_balance - amount));
}
```

## Attack Scenario

1. **Setup**: Attacker deposits 100 underlying tokens, receives 100 wrapper shares
2. **First unwrap**: Attacker calls `unwrap(100)` → receives 100 underlying tokens
3. **Wrapper balance unchanged**: Attacker still has 100 wrapper shares (not burned!)
4. **Refill custody**: Another user deposits tokens, or attacker deposits again
5. **Second unwrap**: Attacker calls `unwrap(100)` again → receives another 100 underlying tokens
6. **Repeat**: Continue until custody is completely drained

### Example Attack

```rust
// Attacker wraps 100 tokens
wrapper.wrap(&attacker, &100);
// Balance: 100 wrapper shares, 900 underlying tokens

// First unwrap
wrapper.unwrap(&attacker, &100);
// Balance: 100 wrapper shares (BUG!), 1000 underlying tokens

// Refill custody
wrapper.wrap(&attacker, &100);

// Second unwrap with SAME shares
wrapper.unwrap(&attacker, &100);
// Balance: 100 wrapper shares (still!), 1000 underlying tokens

// Attacker has drained 200 tokens using only 100 wrapper shares
```

## Impact

- **Complete custody drain**: Attackers can extract all underlying tokens
- **Infinite money glitch**: Same wrapper shares can be reused indefinitely
- **Loss of funds**: Legitimate users lose their deposited tokens
- **Protocol insolvency**: Wrapper becomes unbacked and worthless

## Secure Fix

The secure implementation (`src/secure.rs`) fixes this by burning wrapper shares **before** transferring underlying tokens, following the checks-effects-interactions pattern:

```rust
pub fn unwrap(env: Env, user: Address, amount: i128) {
    user.require_auth();

    // Checks
    if current_balance < amount {
        panic!("insufficient wrapper balance");
    }

    // ✅ Effects: Burn wrapper shares FIRST
    env.storage()
        .persistent()
        .set(&balance_key, &(current_balance - amount));

    let total_supply: i128 = env
        .storage()
        .persistent()
        .get(&DataKey::TotalSupply)
        .unwrap_or(0);
    env.storage()
        .persistent()
        .set(&DataKey::TotalSupply, &(total_supply - amount));

    // Interactions: Transfer underlying tokens AFTER burning
    let token_client = token::TokenClient::new(&env, &underlying_token);
    token_client.transfer(&env.current_contract_address(), &user, &amount);
}
```

## Key Principles

1. **Checks-Effects-Interactions**: Update state before external calls
2. **Burn before transfer**: Always decrement balances before releasing assets
3. **Atomic operations**: Ensure balance updates and transfers are consistent
4. **Invariant preservation**: Maintain `total_supply == custody_balance` at all times

## Testing

Run the tests to see the vulnerability in action:

```bash
cargo test -p unwrap-without-burn
```

Key tests:
- `test_double_unwrap_succeeds`: Demonstrates unwrapping twice with same shares
- `test_repeated_unwrap_drains_custody`: Shows custody drainage attack
- `test_secure_prevents_double_unwrap`: Secure version prevents the attack
- `test_secure_burns_shares_correctly`: Secure version correctly decrements balances

## Real-World Examples

This vulnerability class has appeared in:
- **Wrapped token contracts** that forget to burn shares
- **Vault contracts** that release collateral without updating debt
- **Staking contracts** that pay rewards without decrementing stake
- **Bridge contracts** that unlock tokens without burning bridge shares

## Prevention

1. **Always burn/decrement before transfer**: Update balances before releasing assets
2. **Follow CEI pattern**: Checks → Effects → Interactions
3. **Test double-spend scenarios**: Verify operations can't be repeated
4. **Audit state changes**: Ensure all relevant state is updated
5. **Use reentrancy guards**: Prevent recursive calls (though not the issue here)

## References

- [Checks-Effects-Interactions Pattern](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern)
- [CWE-841: Improper Enforcement of Behavioral Workflow](https://cwe.mitre.org/data/definitions/841.html)
- [SWC-107: Reentrancy](https://swcregistry.io/docs/SWC-107) (related pattern)
