# `vulnerable/merkle_leaf_missing_amount`

## Vulnerability: Merkle Leaf Omits Token Amount

**Severity:** Critical

## Description

The contract constructs the Merkle leaf hash using only the claimant address, omitting the claimed amount. This allows an attacker to claim any amount as long as their address appears in the tree, bypassing the amount-based validation that should be enforced by the Merkle proof.

## Exploit Scenario

1. The merkle tree is built with `leaf = hash(claimant_address)` (missing amount).
2. A legitimate claimant is allocated 100 tokens, their address is in the tree.
3. The attacker claims 10,000 tokens using the same proof.
4. The vulnerable contract verifies the proof successfully because amount is not part of the leaf.
5. Attacker receives inflated amount.

## Vulnerable Code

```rust
fn leaf_hash(env: &Env, claimant: &Address) -> BytesN<32> {
    // ❌ Amount is missing — any amount will be accepted
    env.crypto().sha256(&claimant.to_xdr(env))
}

pub fn claim(env: Env, claimant: Address, amount: i128, proof: Vec<BytesN<32>>) {
    verify_merkle_proof(&env, &claimant, &proof);  // amount not included in verification
    // Transfer any amount
    transfer(&claimant, &amount);
}
```

## Secure Fix

Include the amount (and optionally campaign_id and domain) in the leaf hash so the claimed amount is bound by the Merkle proof.

```rust
fn leaf_hash(env: &Env, claimant: &Address, amount: i128, campaign_id: u32, domain: &Address) -> BytesN<32> {
    // ✅ SECURE: amount is included in the leaf
    let mut data = Bytes::new(env);
    data.append(&claimant.to_xdr(env));
    data.extend_from_array(&amount.to_be_bytes());
    data.extend_from_array(&campaign_id.to_be_bytes());
    data.append(&domain.to_xdr(env));
    env.crypto().sha256(&data)
}
```

See the inline `secure.rs` module inside this crate for the full corrected implementation.

## References

- [docs/vulnerabilities.md](../../docs/vulnerabilities.md)
- [docs/threat_model.md](../../docs/threat_model.md)
