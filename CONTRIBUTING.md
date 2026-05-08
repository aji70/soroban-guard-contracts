# Contributing to soroban-guard-contracts

Thanks for helping grow the library. This guide covers everything you need to
add a new vulnerable contract example, run the test suite, and get your PR
merged.

---

## Sister repos

| Repo | Purpose |
|---|---|
| [soroban-guard-core](https://github.com/Veritas-Vaults-Network/soroban-guard-core) | CLI scanner that analyses contracts against this library |
| [soroban-guard-web](https://github.com/Veritas-Vaults-Network/soroban-guard-web) | Web dashboard for browsing scan results from the on-chain registry |

---

## 1. Setting up a local Soroban dev environment

### Prerequisites

- Rust toolchain (stable) — install via [rustup](https://rustup.rs)
- `wasm32-unknown-unknown` target
- Stellar CLI (for deploying to testnet, optional for local testing)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add the WASM target
rustup target add wasm32-unknown-unknown

# Install Stellar CLI (optional — needed for testnet deployment)
cargo install --locked stellar-cli --features opt
```

### Clone and build

```bash
git clone https://github.com/Veritas-Vaults-Network/soroban-guard-contracts
cd soroban-guard-contracts
cargo build
```

---

## 2. Compiling and testing contracts

### Run all tests

```bash
cargo test
```

### Run tests for a single contract

```bash
cargo test -p missing-auth
cargo test -p registry
```

### Build optimised WASM (for deployment)

```bash
cargo build --release --target wasm32-unknown-unknown
# Output: target/wasm32-unknown-unknown/release/<name>.wasm
```

---

## 3. Adding a new vulnerable contract

### Step-by-step

1. **Create the crate**

```bash
mkdir -p vulnerable/<your_name>/src
```

2. **Add `Cargo.toml`**

```toml
[package]
name = "your-name"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = { workspace = true }
```

3. **Register it in the workspace** — add `"vulnerable/<your_name>"` to the
   `members` array in the root `Cargo.toml`.

4. **Write the contract** in `src/lib.rs`. See the checklist below.

5. **Add a `#[cfg(test)]` module** with at least 3 tests — one of which must
   demonstrate the vulnerability succeeding (i.e. the bad thing happens without
   a panic).

6. **Document the vulnerability** — add a new section to `docs/vulnerabilities.md`
   following the existing format.

7. **Verify it compiles and tests pass**

```bash
cargo test -p your-name
```

---

## 4. What makes a good vulnerable contract

A good example contract must satisfy all of the following:

### Realistic context
The contract should model something a real developer might write — a token,
vault, staking pool, escrow, DAO, NFT marketplace, etc. Toy contracts with no
business logic are harder to learn from.

### Compilable
The contract must compile against the current workspace `soroban-sdk` version
with zero errors and zero `todo!()` macros. Run `cargo build` before opening
a PR.

### Clearly flawed — not subtly broken
The vulnerability must be obvious enough that a scanner (human or automated)
can identify it from the source. Mark every flaw with a comment:

```rust
// VULNERABILITY: <explain what's wrong and why it matters>
// ❌ Missing: <show what the fix would look like>
```

### One primary vulnerability per contract
Each contract should demonstrate a single class of vulnerability. Combining
multiple issues in one file makes it harder to use as a targeted test case.

### Matching secure mirror
Every vulnerable contract should have a corresponding secure version in
`secure/` with `// ✅ FIX:` comments explaining each change.

### At least 3 tests
- One test that shows normal operation works.
- One test that demonstrates the vulnerability (the bad thing succeeds).
- One test that verifies a boundary condition or edge case.

---

## 5. Code style

- `#![no_std]` on all contracts.
- Use `#[contracttype]` for all storage keys and custom structs.
- No `unwrap()` in production paths — use `.expect("descriptive message")` or
  explicit error handling.
- Keep functions short and single-purpose.
- Run `cargo fmt` before committing.

---

## 6. Commit conventions

This repo targets a minimum of 25 meaningful commits. Each commit should be
scoped to a single logical change:

```
feat(missing_auth): add vulnerable token contract
feat(missing_auth): add test suite demonstrating auth bypass
fix(secure_vault): add balance underflow guard
docs: add missing_auth entry to vulnerabilities.md
```

---

## 7. Opening a PR

1. Fork the repo and create a branch: `feat/vuln-<name>` or `fix/<name>`.
2. Ensure `cargo test` passes with zero failures.
3. Ensure `cargo fmt --check` passes.
4. Fill in the PR template — link to the relevant `docs/vulnerabilities.md`
   section and describe the real-world scenario the contract models.

---

## 8. Adding a New Vulnerability Pair

This section walks you through adding a new `vulnerable/<name>` + `secure/<name>` pair from scratch.

### Naming conventions

- Use `snake_case` for all directory and crate names (e.g. `missing_auth`, `dust_griefing`).
- Names should be descriptive of the vulnerability class, not the contract type.
- The vulnerable crate is named `<name>` and lives in `vulnerable/<name>`.
- The secure mirror is either a new crate in `secure/<name>` **or** an inline `secure` module at `vulnerable/<name>/src/secure.rs` — use whichever keeps the diff smallest.

### Step-by-step

**1. Create the vulnerable crate**

```
vulnerable/
  <name>/
    Cargo.toml
    src/
      lib.rs
```

`Cargo.toml` minimum:

```toml
[package]
name = "<name>"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
soroban-sdk = { workspace = true }
```

**2. Create the secure mirror**

Option A — separate crate (preferred when the secure version is substantially different):

```
secure/
  <name>/
    Cargo.toml
    src/
      lib.rs
```

Option B — inline module (preferred for small fixes):

```rust
// vulnerable/<name>/src/lib.rs
pub mod secure;   // points to vulnerable/<name>/src/secure.rs
```

**3. Register both crates in the workspace**

Add to the `members` array in the root `Cargo.toml`:

```toml
"vulnerable/<name>",
"secure/<name>",   # omit if using inline secure module
```

**4. Write the vulnerable contract**

- Add a module-level `//!` doc block explaining the vulnerability class, the missing guard, and the severity.
- Add `/// rustdoc` to every `pub fn` covering: what it does, what is missing, and the impact.
- Mark every flaw with an inline comment:

```rust
// ❌ Missing: <what the fix looks like>
```

**5. Write the secure mirror**

- Mirror every vulnerable function with the fix applied.
- Mark each fix with:

```rust
// ✅ FIX: <explain the change>
```

**6. Write tests — minimum 3 per contract**

| Test | Purpose |
|---|---|
| `test_normal_<action>_works` | Happy path — normal operation succeeds |
| `test_<vulnerability>_<effect>` | Demonstrates the vulnerability (bad thing happens) |
| `test_secure_rejects_<attack>` | Secure mirror blocks the same attack |

**7. Add a `docs/vulnerabilities.md` entry**

Follow the existing format:

```markdown
## N. <Title> (`<name>`)

**Contract:** `vulnerable/<name>` → `secure/<name>`
**Severity:** Critical / High / Medium / Low

### What it is
...

### Vulnerable pattern
```rust
// ❌ ...
```

### Secure fix
```rust
// ✅ ...
```

### Impact
...
```

**8. Verify everything**

```bash
cargo build -p <name>
cargo test -p <name>
cargo fmt --check
cargo doc --workspace --no-deps   # must produce zero warnings
```

**9. Open a PR**

- Branch name: `feat/vuln-<name>`
- PR title: `feat(<name>): add vulnerable/secure pair for <vulnerability class>`
- Link to the `docs/vulnerabilities.md` section you added.
- Reference the issue number if one exists.
