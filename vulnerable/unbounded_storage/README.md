# `vulnerable/unbounded_storage`

## Vulnerability: Unbounded Storage Growth

**Severity:** Medium

## Description

The contract appends entries to a collection (e.g. a history list or participant registry) without any cap. An attacker can grow the collection indefinitely, causing storage rent to skyrocket and making reads/writes prohibitively expensive or impossible.

## Exploit Scenario

1. Attacker calls `register()` or `submit()` thousands of times from different addresses.
2. Each call appends an entry to an unbounded `Vec` in persistent storage.
3. The storage entry grows until reads hit host memory limits or rent becomes unaffordable.

## Vulnerable Code

```rust
pub fn register(env: Env, account: Address) {
    let mut list: Vec<Address> = get_list(&env);
    list.push_back(account); // ❌ no cap
    set_list(&env, &list);
}
```

## Secure Fix

```rust
const MAX_ENTRIES: u32 = 1000;
assert!(list.len() < MAX_ENTRIES, "registry full"); // ✅
list.push_back(account);
```

No separate secure crate — the fix is an inline cap.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
