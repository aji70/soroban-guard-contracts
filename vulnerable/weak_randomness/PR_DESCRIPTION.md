# feat: Vulnerable lottery with predictable randomness and commit-reveal secure mirror

Implements the "front-running via predictable randomness" vulnerability pattern.

## Vulnerable pattern

```rust
pub fn pick_winner(env: Env) -> Address {
    let participants: Vec<Address> = /* ... */;
    // ❌ Ledger sequence is known in advance — validators can time their entry
    let idx = (env.ledger().sequence() as u32) % (participants.len() as u32);
    participants.get(idx).unwrap()
}
```

`env.ledger().sequence()` is public, deterministic, and known before a
transaction is submitted. It provides zero unpredictability as a randomness
source.

## Secure fix

`secure::CommitRevealLottery` implements a two-phase commit-reveal scheme:

1. **Commit** — each participant submits `SHA-256(secret_nonce)`.
2. **Reveal** — each participant reveals their nonce; the contract verifies
   the hash and XORs all nonces into a shared seed.
3. **Draw** — `seed % participants.len()` selects the winner once all
   participants have revealed.

No single party can bias the seed without knowing all others' secrets first.
For production, a VRF oracle provides the strongest guarantee.

## What's added

- `WeakRandomnessLottery` — lottery whose `pick_winner` uses
  `ledger().sequence() % participants.len()` as sole randomness source.
- `secure::CommitRevealLottery` — commit-reveal lottery with SHA-256
  commitment verification and XOR seed accumulation.

## Tests

| Test | Contract | Expected |
|---|---|---|
| `test_winner_determined_by_sequence` | Vulnerable | pass — outcome changes predictably with sequence |
| `test_same_sequence_always_picks_same_winner` | Vulnerable | pass — same sequence, same winner every time |
| `test_attacker_can_predict_and_time_winning_call` | Vulnerable | pass — attacker times call to guarantee win |
| `test_secure_full_round` | Secure | pass — commit-reveal produces correct winner |
| `test_secure_draw_requires_all_reveals` | Secure | expected panic — draw blocked until all reveal |
| `test_secure_reveal_rejects_wrong_nonce` | Secure | expected panic — wrong nonce rejected |

**Severity:** High
