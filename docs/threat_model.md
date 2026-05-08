# Threat Model — soroban-guard-contracts

This document describes the security model for the contracts in this repository.
It is intended for security reviewers, auditors, and contributors.

---

## Actors

| Actor     | Trust Level | Capabilities |
|-----------|-------------|--------------|
| Admin     | High        | Upgrade contracts, rotate keys, add/remove scanners, dispute scans, set parameters |
| Scanner   | Medium      | Submit scan results for registered contracts (must be approved by admin) |
| Staker    | Low         | Stake tokens, unstake, claim rewards — only over their own funds |
| Attacker  | None        | Controls one or more addresses; assumed to call any public function with arbitrary inputs |

---

## Assets at Risk

| Asset | Location | Impact if compromised |
|-------|----------|-----------------------|
| Token balances | vault / staking contracts | Direct financial loss |
| Admin private key | off-chain key store | Full contract takeover |
| Scan record integrity | `registry` contract | False security signals; scanners trusted incorrectly |
| Allowances | token contracts | Unauthorised spend on behalf of another account |
| Staking rewards | staking contracts | Reward pool drained |
| Contract WASM | upgrade path | Arbitrary code execution after upgrade |

---

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│  Stellar Network (on-chain)                             │
│                                                         │
│  ┌──────────────┐   submit_scan()   ┌───────────────┐  │
│  │  Scanner CLI │ ────────────────► │   registry    │  │
│  │  (off-chain) │                   │  (admin-gated │  │
│  └──────────────┘                   │   scanner set)│  │
│                                     └───────────────┘  │
│                                                         │
│  ┌──────────────┐                   ┌───────────────┐  │
│  │  User / EOA  │ ──── transfer ──► │  vault /      │  │
│  │  (staker)    │                   │  staking      │  │
│  └──────────────┘                   └───────────────┘  │
│                                                         │
│  ┌──────────────┐                                       │
│  │  Admin EOA   │ ── upgrade / add_scanner / dispute ─► │
│  └──────────────┘                                       │
└─────────────────────────────────────────────────────────┘
```

**Key boundaries:**

- The `registry` trusts only admin-approved scanner addresses. An unapproved address cannot submit scan results.
- Vault and staking contracts trust only the account that owns the funds (`require_auth`).
- The admin is trusted to act honestly; admin key compromise is an out-of-scope operational risk (see below).
- Off-chain scanner CLI is trusted to produce correct findings hashes; the registry stores them without validation.

---

## Attack Vectors

### In-scope

| ID  | Vector | Class | Demonstrated by |
|-----|--------|-------|-----------------|
| AV-01 | Call state-mutating function without `require_auth` | Missing authorisation | [`missing_auth`](../vulnerable/missing_auth/README.md) |
| AV-02 | Arithmetic overflow / underflow in reward or balance calc | Integer overflow | [`unchecked_math`](../vulnerable/unchecked_math/README.md), [`underflow_transfer`](../vulnerable/underflow_transfer/README.md) |
| AV-03 | Persistent storage entry expires (TTL not renewed) | Storage expiry | [`missing_ttl`](../vulnerable/missing_ttl/README.md) |
| AV-04 | Call `set_admin` or `upgrade` without admin check | Privilege escalation | [`unprotected_admin`](../vulnerable/unprotected_admin/README.md) |
| AV-05 | Write to any account's storage slot | Unauthorised writes | [`unsafe_storage`](../vulnerable/unsafe_storage/README.md) |
| AV-06 | Claim rewards multiple times from same stake window | Double-claim | [`double_claim`](../vulnerable/double_claim/README.md) |
| AV-07 | Divide by zero in fee or rate calculation | Division by zero | [`div_by_zero`](../vulnerable/div_by_zero/README.md) |
| AV-08 | Transfer negative amount to inflate balance | Negative amount | [`negative_transfer`](../vulnerable/negative_transfer/README.md) |
| AV-09 | Re-initialise an already-initialised contract | Re-initialisation | [`reinit_attack`](../vulnerable/reinit_attack/README.md) |
| AV-10 | Emit sensitive data (keys, PII) in contract events | Sensitive data in events | [`leaky_events`](../vulnerable/leaky_events/README.md) |
| AV-11 | Use string instead of `Address` type for admin | String-typed admin | [`string_admin`](../vulnerable/string_admin/README.md) |
| AV-12 | Admin transfers ownership without two-step confirmation | Admin rug-pull | [`admin_rugpull`](../vulnerable/admin_rugpull/README.md) |
| AV-13 | Zero-value deposit accepted, griefing storage | Zero-value deposit | [`zero_deposit`](../vulnerable/zero_deposit/README.md) |
| AV-14 | Dust deposits fill storage cheaply | Dust griefing | [`dust_griefing`](../vulnerable/dust_griefing/README.md) |
| AV-15 | Oracle price read from single instant source | Oracle manipulation | [`instant_oracle`](../vulnerable/instant_oracle/README.md) |
| AV-16 | Swap with no minimum output guard | Slippage | [`no_slippage`](../vulnerable/no_slippage/README.md) |
| AV-17 | Flash loan repayment not checked before return | Flash-loan re-entry | [`flash_loan_no_check`](../vulnerable/flash_loan_no_check/README.md) |
| AV-18 | Scanner address not verified against on-chain registry | Scanner spoofing | [`scanner_impersonation`](../vulnerable/scanner_impersonation/README.md) |
| AV-19 | Allowance not decremented after spend | Allowance bug | [`allowance_not_decremented`](../vulnerable/allowance_not_decremented/README.md) |
| AV-20 | Storage keys collide across different data types | Key collision | [`key_collision`](../vulnerable/key_collision/README.md) |
| AV-21 | Burn tokens without owner authorisation | Unprotected burn | [`unprotected_burn`](../vulnerable/unprotected_burn/README.md) |
| AV-22 | Fee withdrawal open to any caller | Fee drain | [`unprotected_fee_withdraw`](../vulnerable/unprotected_fee_withdraw/README.md) |
| AV-23 | Delete contract storage without admin check | Storage wipe | [`unprotected_delete`](../vulnerable/unprotected_delete/README.md) |
| AV-24 | Emergency withdraw open to any caller | Emergency drain | [`unprotected_emergency_withdraw`](../vulnerable/unprotected_emergency_withdraw/README.md) |
| AV-25 | Self-transfer inflates or corrupts balance | Self-transfer | [`self_transfer`](../vulnerable/self_transfer/README.md) |
| AV-26 | Re-entrant call before state is committed | Re-entrancy | [`reentrancy`](../vulnerable/reentrancy/README.md) |
| AV-27 | Admin set to zero address | Zero address admin | [`zero_admin`](../vulnerable/zero_admin/README.md) |
| AV-28 | Zero-value stake accepted | Zero-value stake | [`zero_stake`](../vulnerable/zero_stake/README.md) |
| AV-29 | Lock expiry based on `ledger().timestamp()` (manipulable) | Timestamp manipulation | [`timestamp_lock`](../vulnerable/timestamp_lock/README.md) |
| AV-30 | No events emitted; off-chain indexers blind | Missing events | [`missing_events`](../vulnerable/missing_events/README.md) |
| AV-31 | Sensitive data stored in plain contract storage | Sensitive storage | [`sensitive_storage`](../vulnerable/sensitive_storage/README.md) |
| AV-32 | Replay attack — nonce or signature not invalidated | Replay | [`replay_attack`](../vulnerable/replay_attack/README.md) |
| AV-33 | Unbounded storage growth (no cap on entries) | Unbounded storage | [`unbounded_storage`](../vulnerable/unbounded_storage/README.md) |
| AV-34 | Uncapped interest / reward rate | Uncapped rate | [`uncapped_rate`](../vulnerable/uncapped_rate/README.md) |
| AV-35 | Oracle price used after staleness window | Stale oracle | [`stale_oracle`](../vulnerable/stale_oracle/README.md) |
| AV-36 | Unsafe integer cast (e.g. `u64 as i64`) | Unsafe cast | [`unsafe_cast`](../vulnerable/unsafe_cast/README.md) |
| AV-37 | Mint function open to any caller | Unprotected mint | [`unprotected_mint`](../vulnerable/unprotected_mint/README.md) |
| AV-38 | Recursive / deep call stack exhaustion | Call depth | [`call_depth`](../vulnerable/call_depth/README.md) |

### Out-of-scope

| Vector | Reason |
|--------|--------|
| Admin private key theft | Operational / key-management risk; outside contract logic |
| Stellar network-level attacks (consensus, eclipse) | Protocol-level; not addressable in contract code |
| Front-running via MEV | Stellar's fee-bump mechanism partially mitigates; not modelled here |
| Off-chain scanner CLI bugs | Separate codebase (`soroban-guard-core`) |

---

## Mitigations

| ID  | Mitigation | Secure reference |
|-----|-----------|-----------------|
| AV-01 | `require_auth()` on every state-mutating call | `secure_vault`, `protected_admin` |
| AV-02 | `checked_add` / `checked_sub` / `checked_mul`; reject negative amounts | `secure_vault` |
| AV-03 | Call `extend_ttl()` on every persistent write | inline `secure.rs` in `missing_ttl` |
| AV-04 | Admin auth check before `set_admin` / `upgrade` | `protected_admin` |
| AV-05 | Account auth before writing to per-account storage | `protected_admin` |
| AV-06 | Claim flag written to storage before reward transfer | inline `secure.rs` in `double_claim` |
| AV-07 | Guard divisor `> 0` before division | inline fix |
| AV-08 | Reject `amount <= 0` at function entry | inline `secure.rs` in `negative_transfer` |
| AV-09 | Initialised flag in persistent storage; panic if already set | inline fix |
| AV-10 | Emit only non-sensitive fields in events | inline `secure.rs` in `leaky_events` |
| AV-11 | Use `Address` type for all admin / account fields | inline `secure.rs` in `string_admin` |
| AV-12 | Two-step admin transfer (propose + accept) | inline `secure.rs` in `admin_rugpull` |
| AV-13 | Guard `amount > 0` at deposit entry | inline `secure.rs` in `zero_deposit` |
| AV-14 | Minimum deposit threshold | `secure/dust_griefing` |
| AV-15 | TWAP or multi-source oracle | inline `secure.rs` in `instant_oracle` |
| AV-16 | `min_out` slippage guard | inline `secure.rs` in `no_slippage` |
| AV-17 | Repayment check before returning from flash loan | inline `secure.rs` in `flash_loan_no_check` |
| AV-18 | On-chain scanner registry check in `registry` | `registry`, inline `secure.rs` in `scanner_impersonation` |
| AV-19 | Decrement allowance after every spend | inline `secure.rs` in `allowance_not_decremented` |
| AV-20 | Namespaced storage keys (enum variants per data type) | inline `secure.rs` in `key_collision` |
| AV-21 | `require_auth()` on burn | `secure_burn` |
| AV-22 | Admin auth on fee withdrawal | `protected_fee_withdraw` |
| AV-23 | Admin auth on storage delete | inline fix |
| AV-24 | Auth + time-lock on emergency withdraw | inline `secure.rs` in `unprotected_emergency_withdraw` |
| AV-25 | Reject `from == to` at transfer entry | inline fix |
| AV-26 | Checks-effects-interactions; write state before external calls | inline `secure.rs` in `reentrancy` |
| AV-27 | Reject zero address at initialisation | inline fix |
| AV-28 | Guard `amount > 0` at stake entry | inline `secure.rs` in `zero_stake` |
| AV-29 | Use `ledger().sequence()` instead of `ledger().timestamp()` | `secure/sequence_lock` |
| AV-30 | Emit structured events on every state change | inline fix |
| AV-31 | Never store secrets on-chain; use off-chain key management | inline fix |
| AV-32 | Invalidate nonce / signature in storage before processing | inline `secure.rs` in `replay_attack` |
| AV-33 | Cap collection size; use pagination | inline fix |
| AV-34 | Cap rate at a protocol-defined maximum | inline `secure.rs` in `uncapped_rate` |
| AV-35 | Reject oracle data older than staleness window | inline `secure.rs` in `stale_oracle` |
| AV-36 | Use safe cast helpers; validate range before cast | inline fix |
| AV-37 | Admin auth on mint | inline fix |
| AV-38 | Limit recursion depth; avoid unbounded call chains | inline fix |

---

## Registry-specific trust model

The `registry` contract has an elevated attack surface because it is the
authoritative source of scan results consumed by dashboards and the scanner CLI.

- **Scanner spoofing (AV-18):** Any address can call `submit_scan` on a naive
  registry. The registry mitigates this by maintaining an admin-controlled
  allowlist and requiring `scanner.require_auth()`.
- **Batch DoS (registry `get_latest_scans_batch`):** Accepting an unbounded
  input vector would exhaust host memory. The function caps input at 20
  addresses and panics otherwise.
- **Score manipulation:** Only the admin can call `dispute_scan`. Scanners
  cannot inflate their own score beyond one increment per submission.

---

## See also

- [docs/vulnerabilities.md](./vulnerabilities.md) — detailed per-class write-ups with code examples
- [vulnerable/*/README.md](../vulnerable/) — per-crate exploit scenarios and fixes
- [CONTRIBUTING.md](../CONTRIBUTING.md) — how to add new vulnerable contract examples
