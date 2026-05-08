# `vulnerable/<crate_name>`

## Vulnerability: <Name>

**Severity:** <Critical | High | Medium | Low>

## Description

<2–3 sentences describing the flaw and why it is dangerous.>

## Exploit Scenario

1. Attacker calls `<function>` with `<parameters>`.
2. Contract executes without checking `<invariant>`.
3. Attacker gains `<outcome>`.

## Vulnerable Code

```rust
// see src/lib.rs
<paste the vulnerable snippet here>
```

## Secure Fix

```rust
// corrected version
<paste the fixed snippet here>
```

See [`secure/<mirror_crate>`](../../secure/<mirror_crate>) for the full corrected implementation,
or the inline `secure.rs` module inside this crate if no separate secure crate exists.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
