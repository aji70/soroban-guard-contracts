# reward_checkpoint_missing

**Severity:** High  
**Category:** Staking / Reward accounting

## Vulnerability

When a user calls `stake`, the contract records the new balance but does
**not** set `reward_debt` to the current accumulator value. Because
`reward_debt` defaults to 0, the user's pending reward is immediately
calculated as if they had been staking since the contract was deployed:

```
pending = (acc_reward_per_share × new_stake / SCALE) − 0
```

A late depositor can therefore claim all rewards that accrued before their
deposit, stealing from earlier stakers.

## Vulnerable code

```rust
pub fn stake(env: Env, user: Address, amount: u64) {
    user.require_auth();
    // ❌ Missing: set_debt(&env, &user, get_acc(&env) * amount / SCALE);
    env.storage().persistent().set(&DataKey::Stake(user.clone()), &amount);
}
```

## Fix

Snapshot the accumulator into `reward_debt` before (or immediately after)
writing the new stake:

```rust
let debt = get_acc(&env).saturating_mul(amount) / SCALE;
set_debt(&env, &user, debt);
env.storage().persistent().set(&DataKey::Stake(user.clone()), &amount);
```

## Impact

An attacker can deposit a large stake in a single transaction, immediately
call `claim_rewards`, and withdraw rewards that were earned by other stakers
over the entire history of the pool.

## Test

```bash
cargo test -p reward-checkpoint-missing
```
