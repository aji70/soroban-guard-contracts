# `vulnerable/replay_attack`

## Vulnerability: Replay Attack (Missing Nonce)

**Severity:** High

## Description

The contract processes signed messages or actions without invalidating them after use. An attacker can capture a valid signed message and replay it multiple times, executing the same action repeatedly.

## Exploit Scenario

1. Alice signs a withdrawal request for 100 tokens.
2. The contract processes the request and pays Alice.
3. Attacker replays the same signed message; the contract pays out again.
4. Attacker repeats until the pool is drained.

## Vulnerable Code

```rust
pub fn withdraw(env: Env, signature: BytesN<32>, amount: i128) {
    verify_signature(&env, &signature, amount);
    // ❌ Missing: mark signature as used
    do_withdraw(&env, amount);
}
```

## Secure Fix

```rust
assert!(!is_used(&env, &signature), "signature already used"); // ✅
mark_used(&env, &signature);
do_withdraw(&env, amount);
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
