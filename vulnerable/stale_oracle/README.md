# `vulnerable/stale_oracle`

## Vulnerability: Stale Oracle Price

**Severity:** High

## Description

The contract uses an oracle price without checking when it was last updated. If the oracle stops publishing (due to downtime or manipulation), the contract continues operating on an arbitrarily old price, enabling profitable arbitrage against the stale rate.

## Exploit Scenario

1. Oracle stops updating; the last price is 30 minutes old.
2. The real market price has moved 20%.
3. Attacker trades against the contract at the stale price, extracting the price difference.

## Vulnerable Code

```rust
let price = oracle::get_price(&env);
// ❌ Missing: assert!(price.updated_at + MAX_STALENESS >= env.ledger().timestamp());
let value = amount * price.value;
```

## Secure Fix

```rust
let price = oracle::get_price(&env);
assert!(
    price.updated_at + MAX_STALENESS_SECONDS >= env.ledger().timestamp(),
    "oracle price is stale" // ✅
);
let value = amount * price.value;
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
