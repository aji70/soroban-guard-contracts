# `vulnerable/unsafe_storage`

## Vulnerability: Unauthorised Storage Writes

**Severity:** Critical

## Description

The KYC registry allows any caller to write to any account's storage slot. There is no check that the caller is the account being written to, so an attacker can overwrite another user's KYC status or data.

## Exploit Scenario

1. Attacker calls `set_kyc(victim, true)`.
2. Contract writes to the victim's storage slot without verifying the caller is the victim or an authorised admin.
3. Attacker can grant or revoke KYC status for any address.

## Vulnerable Code

```rust
pub fn set_kyc(env: Env, account: Address, status: bool) {
    // ❌ Missing: account.require_auth() or admin check
    env.storage().persistent().set(&DataKey::Kyc(account), &status);
}
```

## Secure Fix

```rust
pub fn set_kyc(env: Env, account: Address, status: bool) {
    account.require_auth(); // ✅ or require_admin(&env) for admin-only writes
    env.storage().persistent().set(&DataKey::Kyc(account), &status);
}
```

See [`secure/protected_admin`](../../secure/protected_admin) for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
