# `vulnerable/rescue_primary_asset`

## Vulnerability: Rescue Function Drains Primary Asset

**Severity:** Critical

## Description

A `rescue_token()` function is intended to recover accidentally sent tokens that are unrelated to the protocol. However, the implementation fails to block the protocol's primary managed asset. Even with admin authorization, this rescue path can drain user deposits and break accounting, effectively allowing a rug-pull of the entire protocol balance.

## Exploit Scenario

1. Users deposit the primary token (e.g., USDC) into a vault contract.
2. Admin calls `rescue_token(primary_token_address, admin_wallet, total_balance)`.
3. The rescue function transfers the primary asset out without checking if it's the managed token.
4. All user deposits are drained; internal accounting becomes invalid.

## Vulnerable Code

```rust
pub fn rescue_token(env: Env, token: Address, recipient: Address, amount: i128) {
    require_admin(&env);
    // ❌ No check that token != managed_token
    // Admin can drain the primary asset users deposited
    token_client.transfer(&env.current_contract_address(), &recipient, &amount);
}
```

## Secure Fix

```rust
pub fn rescue_token(env: Env, token: Address, recipient: Address, amount: i128) {
    require_admin(&env);
    let managed_token: Address = env.storage().persistent()
        .get(&DataKey::ManagedToken).unwrap();
    
    // ✅ Block rescue of the primary protocol asset
    if token == managed_token {
        panic!("cannot rescue managed token");
    }
    
    token_client.transfer(&env.current_contract_address(), &recipient, &amount);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
