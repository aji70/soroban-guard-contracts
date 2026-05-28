# Fake Token Registration

## Vulnerability

An asset registry that trusts caller-supplied symbol and decimals metadata without verification. Attackers can register fake assets that look identical to trusted tokens in downstream views, enabling phishing attacks and user confusion.

## Severity

**High**

## Description

The vulnerable contract allows anyone to register a token with arbitrary metadata (symbol, decimals) without:
1. Admin approval
2. Verification against the actual token contract
3. Checking for duplicate symbols

This enables attackers to:
- Register malicious tokens with trusted symbols (e.g., "USDC", "XLM")
- Create multiple tokens with the same symbol, causing confusion
- Phish users who trust the registry's metadata

## Vulnerable Code

```rust
pub fn register_token(
    env: Env,
    token_address: Address,
    symbol: String,
    decimals: u32,
    caller: Address,
) {
    caller.require_auth();

    // ❌ Missing: Admin approval check
    // ❌ Missing: Verification of symbol/decimals against token contract
    // ❌ Missing: Check for duplicate symbols

    let metadata = TokenMetadata {
        token_address: token_address.clone(),
        symbol,
        decimals,
        registered_by: caller,
        timestamp: env.ledger().timestamp(),
    };

    env.storage()
        .persistent()
        .set(&DataKey::Token(token_address), &metadata);
}
```

## Attack Scenario

1. Attacker deploys a malicious token contract
2. Attacker calls `register_token()` with:
   - `token_address`: their malicious contract
   - `symbol`: "USDC" (or any trusted token symbol)
   - `decimals`: 6 (matching the real USDC)
3. Users query the registry and see "USDC" with correct decimals
4. Users trust the metadata and interact with the fake token
5. Attacker drains user funds or executes other malicious actions

## Secure Fix

The secure implementation (`src/secure.rs`) fixes this by:

1. **Admin-only registration**: Only the admin can register tokens
2. **Duplicate symbol check**: Prevents multiple tokens with the same symbol
3. **Symbol mapping**: Maintains a symbol → address mapping for quick lookups

```rust
pub fn register_token(
    env: Env,
    token_address: Address,
    symbol: String,
    decimals: u32,
) {
    // ✅ Require admin authorization
    Self::require_admin(&env);

    // ✅ Check if token is already registered
    if env.storage().persistent().has(&DataKey::Token(token_address.clone())) {
        panic!("token already registered");
    }

    // ✅ Check for duplicate symbols
    if Self::symbol_exists(&env, &symbol) {
        panic!("symbol already in use");
    }

    // ... rest of implementation
}
```

## Additional Recommendations

1. **Token interface verification**: If the token implements a standard interface (e.g., SEP-41), query the symbol and decimals directly from the token contract and verify they match the provided values
2. **Whitelist approach**: Maintain a curated list of approved tokens rather than allowing arbitrary registration
3. **Multi-sig approval**: Require multiple admin signatures for token registration
4. **Time-lock**: Add a delay between registration and activation to allow for review
5. **Event emission**: Emit events for all registration actions for off-chain monitoring

## Testing

Run the tests to see the vulnerability in action:

```bash
cargo test -p fake-token-registration
```

Key tests:
- `test_fake_token_registration_succeeds`: Demonstrates successful fake token registration
- `test_duplicate_symbol_allowed`: Shows multiple tokens can have the same symbol
- `test_no_admin_approval_required`: Proves anyone can register tokens
- `test_secure_requires_admin_approval`: Secure version requires admin auth
- `test_secure_rejects_duplicate_symbols`: Secure version prevents duplicate symbols

## References

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- Stellar SEP-41: Token Interface Standard
