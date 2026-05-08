# `vulnerable/sensitive_storage`

## Vulnerability: Sensitive Data in Contract Storage

**Severity:** High

## Description

The contract stores sensitive data (private keys, passwords, API secrets) in on-chain persistent storage. All Soroban contract storage is publicly readable by anyone with access to the ledger state, so secrets stored on-chain are immediately compromised.

## Exploit Scenario

1. Contract stores a private key or API secret in persistent storage.
2. Any observer queries the ledger state (via RPC or explorer).
3. The secret is read in plaintext; the attacker uses it to compromise the associated system.

## Vulnerable Code

```rust
env.storage().persistent().set(&DataKey::ApiKey, &secret_key); // ❌ public!
```

## Secure Fix

Never store secrets on-chain. Use off-chain key management (HSM, KMS, or environment variables). Store only public identifiers or hashed commitments on-chain.

```rust
// ✅ Store only a hash commitment, never the secret itself
let commitment = env.crypto().sha256(&secret_bytes);
env.storage().persistent().set(&DataKey::Commitment, &commitment);
```

No separate secure crate — this is an architectural fix.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
