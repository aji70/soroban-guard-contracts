# Public Token Sweep Vulnerability

## Severity: Critical

## Description

This contract demonstrates a critical vulnerability where a token sweep function intended for recovering accidentally transferred tokens lacks proper admin authorization. Any caller can drain arbitrary token balances from the contract to themselves.

## Vulnerability Pattern

The `sweep_tokens` function allows anyone to transfer tokens held by the contract without verifying that the caller is an authorized admin:

```rust
pub fn sweep_tokens(env: Env, token: Address, recipient: Address, amount: i128) {
    // ❌ Missing: admin authorization check
    
    let key = DataKey::TokenBalance(token.clone());
    let balance: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    
    if balance < amount {
        panic!("insufficient balance");
    }

    let new_balance = balance - amount;
    env.storage().persistent().set(&key, &new_balance);
}
```

## Impact

- **Unauthorized Fund Drainage**: Any address can sweep all tokens held by the contract
- **No Access Control**: Missing admin authorization allows public access to privileged operations
- **Complete Loss of Custody**: Contract cannot safely hold tokens for any purpose

## Attack Scenario

1. Contract holds tokens (from deposits, fees, or accidental transfers)
2. Attacker calls `sweep_tokens(token, attacker_address, amount)`
3. Tokens are transferred from contract to attacker without any authorization check
4. Contract is drained, legitimate users lose funds

## Secure Implementation

The secure version in `src/secure.rs` requires admin authorization:

```rust
pub fn sweep_tokens(env: Env, token: Address, recipient: Address, amount: i128) {
    let admin: Address = env
        .storage()
        .persistent()
        .get(&DataKey::Admin)
        .expect("not initialized");
    
    // ✅ Admin must authorize the sweep operation
    admin.require_auth();

    // ... rest of implementation
}
```

## Prevention

1. **Require Admin Authorization**: Always verify caller is admin before privileged operations
2. **Principle of Least Privilege**: Only expose sweep functions to authorized roles
3. **Access Control Lists**: Consider multi-sig or role-based access for sensitive operations
4. **Audit Recovery Functions**: Token sweep/recovery functions are high-risk and need careful review

## Testing

Run the test suite to see the vulnerability in action:

```bash
cargo test -p public-token-sweep
```

Key tests:
- `test_anyone_can_sweep_tokens`: Demonstrates unauthorized sweep
- `test_secure_requires_admin_auth`: Shows secure implementation blocks unauthorized access
