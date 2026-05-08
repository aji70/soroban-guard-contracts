# `vulnerable/scanner_impersonation`

## Vulnerability: Scanner Spoofing

**Severity:** High

## Description

The contract accepts scan result submissions from any address without verifying the caller is a registered scanner. An attacker can submit false scan results, marking vulnerable contracts as safe or safe contracts as vulnerable.

## Exploit Scenario

1. Attacker calls `submit_scan(attacker, target, "clean_hash", counts)`.
2. Contract stores the result without checking the attacker is an approved scanner.
3. Dashboards display the false result; users trust a vulnerable contract.

## Vulnerable Code

```rust
pub fn submit_scan(env: Env, scanner: Address, contract_address: Address, ...) {
    scanner.require_auth();
    // ❌ Missing: verify scanner is in the approved list
    store_result(&env, &contract_address, result);
}
```

## Secure Fix

```rust
pub fn submit_scan(env: Env, scanner: Address, contract_address: Address, ...) {
    scanner.require_auth();
    let approved: bool = env.storage().persistent()
        .get(&DataKey::Scanner(scanner.clone())).unwrap_or(false);
    assert!(approved, "not a verified scanner"); // ✅
    store_result(&env, &contract_address, result);
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
