# `vulnerable/instant_oracle`

## Vulnerability: Oracle Manipulation (Instant Price)

**Severity:** High

## Description

The contract reads a price from a single oracle source at the exact moment of the transaction. An attacker who can influence the oracle (e.g. via a flash loan) can set an arbitrary price for one block, then exploit the contract at that manipulated price.

## Exploit Scenario

1. Attacker takes a flash loan to move the oracle price to an extreme value.
2. Attacker calls the contract function that reads the oracle price.
3. Contract executes at the manipulated price; attacker profits and repays the flash loan.

## Vulnerable Code

```rust
let price = oracle::get_price(&env); // ❌ single instant read
let value = amount * price;
```

## Secure Fix

```rust
let price = oracle::get_twap(&env, TWAP_WINDOW); // ✅ time-weighted average
let value = amount * price;
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
