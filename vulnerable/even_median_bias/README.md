# even_median_bias

**Severity: Medium**

## Vulnerability

A median oracle with an even number of price sources always picks the lower of
the two middle values. An attacker controlling one source can bias prices
downward at liquidation boundaries.

## Vulnerable pattern

```rust
// BUG: for even n, picks the lower middle value (index n/2 - 1).
prices.get(n / 2 - 1).unwrap()
```

## Secure fix

Require an odd number of feeds so the median is always unambiguous:

```rust
assert!(n % 2 == 1, "even feed count");
prices.get(n / 2).unwrap()
```
