# `vulnerable/asset_key_collision`

## Vulnerability: Multi-Asset Vault Key Collision

**Severity:** High

## Description

A multi-asset vault stores all balances in persistent storage keyed **only** by
the user's address.  Because the asset address is not part of the key, depositing
two different assets for the same user writes to the same storage slot.  The
second deposit silently overwrites the first, causing the user to lose their
balance for the first asset with no error or event.

## Exploit Scenario

1. Alice deposits 1 000 units of token A → stored at key `alice`.
2. Alice deposits 500 units of token B → stored at key `alice`, overwriting the
   previous value (now 1 500 instead of two independent balances).
3. Alice's token A balance is gone; the vault reports 1 500 for both assets.
4. A withdrawal for token A drains funds that actually belong to token B.

## Vulnerable Code

```rust
pub fn deposit(env: Env, user: Address, _asset: Address, amount: i128) {
    user.require_auth();
    // ❌ Key is only the user address — asset address is ignored.
    let bal: i128 = env.storage().persistent().get(&user).unwrap_or(0);
    env.storage().persistent().set(&user, &(bal + amount));
}
```

## Secure Fix

Use a composite `#[contracttype]` enum key that encodes both the user and the
asset address.  Each `(user, asset)` pair gets its own storage slot.

```rust
#[contracttype]
pub enum DataKey {
    Balance(Address, Address), // (user, asset)
}

pub fn deposit(env: Env, user: Address, asset: Address, amount: i128) {
    user.require_auth();
    // ✅ Composite key — unique per (user, asset) pair.
    let key = DataKey::Balance(user.clone(), asset.clone());
    let bal: i128 = env.storage().persistent().get(&key).unwrap_or(0);
    env.storage().persistent().set(&key, &(bal + amount));
}
```

See the inline `secure.rs` module inside this crate for the full corrected
implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
