# Security Policy

## About This Repository

`soroban-guard-contracts` is an **educational** repository containing intentionally
vulnerable Soroban smart contracts used to test the
[Soroban Guard](https://github.com/Veritas-Vaults-Network/soroban-guard-core) scanner.
The vulnerable contracts are broken **by design** — please do not report their
weaknesses as security issues.

Real vulnerabilities to report are those in:
- The **registry** contract (on-chain scan result storage)
- The **Soroban Guard scanner** ([soroban-guard-core](https://github.com/Veritas-Vaults-Network/soroban-guard-core))
- The **CI/CD pipeline or tooling** in this repo

## Supported Versions

| Component | Supported |
|---|---|
| `registry` contract (latest `main`) | ✅ |
| Vulnerable example contracts | ❌ intentionally broken |
| Secure example contracts | ✅ |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Use GitHub's private vulnerability reporting instead:
👉 [Report a vulnerability](https://github.com/Veritas-Vaults-Network/soroban-guard-contracts/security/advisories/new)

Include:
- A clear description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The potential impact
- Any suggested fix (optional)

## Response Timeline

| Milestone | Target |
|---|---|
| Acknowledgement | Within **48 hours** |
| Initial assessment | Within **5 days** |
| Fix or mitigation | Within **7 days** for critical issues |
| Public disclosure | Coordinated with the reporter |

## Out of Scope

- Vulnerabilities in the `vulnerable/` contracts — they are intentional
- Issues in third-party dependencies (report to the upstream maintainer)
- Theoretical attacks with no practical exploit path
- Findings from automated scanners without manual verification
