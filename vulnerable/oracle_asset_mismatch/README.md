# oracle_asset_mismatch

**Severity: Critical**

## Vulnerability

A price adapter requests a price for one asset but never verifies that the
returned feed's asset id matches the requested asset. An attacker can substitute
a high-value feed for a low-value asset, inflating collateral values.

## Vulnerable pattern

```rust
// BUG: feed_asset is used directly — requested_asset is never checked.
pub fn get_price_vulnerable(env: Env, _requested_asset: Symbol, feed_asset: Symbol) -> i128 {
    env.storage().temporary().get(&DataKey::Feed(feed_asset)).unwrap_or(0)
}
```

## Secure fix

```rust
pub fn get_price(env: Env, requested_asset: Symbol, feed_asset: Symbol) -> i128 {
    if requested_asset != feed_asset {
        panic!("asset mismatch");
    }
    env.storage().temporary().get(&DataKey::Feed(feed_asset)).unwrap_or(0)
}
```
