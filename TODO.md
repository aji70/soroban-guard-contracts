# TODO

- [ ] Implement new vulnerable crate: `vulnerable/public_role_grant/`
  - [ ] Add Cargo.toml + README
  - [ ] Add `src/lib.rs` with vulnerable role-management fixture:
    - [ ] Storage keys: Admin, Operator
    - [ ] Public/unauthenticated `vulnerable_entry(env, actor, amount)` that grants operator
    - [ ] Operator-only restricted function
    - [ ] Tests showing exploit succeeds + boundary condition
  - [ ] Add `src/secure.rs` secure mirror:
    - [ ] Admin-gated grant/revoke with require_auth
    - [ ] Emit events only after successful writes
    - [ ] Tests demonstrating secure rejects unsafe call / preserves invariant
- [ ] Update root `Cargo.toml` workspace members to include the new crate
- [ ] Run `cargo test` for the new crate (and workspace if needed)

