# reward_debt_not_updated

**Severity:** High  
**Category:** Staking / Reward accounting

## Vulnerability

`claim_rewards` computes pending rewards as:

```
pending = (acc_reward_per_share × stake / SCALE) − reward_debt
```

but **never writes the updated `reward_debt` back to storage** after paying
out. On every subsequent call the debt snapshot remains at its original value,
so `pending` is identical each time. An attacker can drain the reward pool by
calling `claim_rewards` in a loop.

## Vulnerable code

```rust
pub fn claim_rewards(env: Env, user: Address) -> u64 {
    user.require_auth();
    let entitled = get_acc(&env).saturating_mul(get_stake(&env, &user)) / SCALE;
    let pending   = entitled.saturating_sub(get_debt(&env, &user));
    // ❌ Missing: set_debt(&env, &user, entitled);
    pending
}
```

## Fix

Add the debt update immediately after computing `entitled`:

```rust
set_debt(&env, &user, entitled);
```

## Impact

Any staker can repeatedly call `claim_rewards` within the same transaction
batch and receive the same reward amount each time, draining the pool until
it is empty.

## Test

```bash
cargo test -p reward-debt-not-updated
```
