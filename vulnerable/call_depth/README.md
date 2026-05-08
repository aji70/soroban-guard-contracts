# `vulnerable/call_depth`

## Vulnerability: Call Depth Exhaustion

**Severity:** Medium

## Description

The contract makes recursive or deeply nested cross-contract calls without limiting the call depth. Soroban enforces a maximum call stack depth; an attacker can craft a call chain that hits this limit, causing an uncontrolled trap and potentially leaving the contract in an inconsistent state.

## Exploit Scenario

1. Attacker deploys a contract that calls back into the vulnerable contract.
2. The vulnerable contract calls the attacker's contract, which calls back, and so on.
3. The call stack hits the Soroban limit; the transaction fails with a trap.
4. If state was partially written before the trap, the contract may be in an inconsistent state.

## Vulnerable Code

```rust
pub fn process(env: Env, next: Address) {
    // ❌ No depth limit — can be chained arbitrarily
    ContractClient::new(&env, &next).process(&env.current_contract_address());
}
```

## Secure Fix

Track call depth in storage and reject calls that exceed a safe limit.

```rust
let depth: u32 = env.storage().temporary().get(&DataKey::Depth).unwrap_or(0);
assert!(depth < MAX_DEPTH, "call depth exceeded"); // ✅
```

No separate secure crate — the fix is an inline depth guard.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
