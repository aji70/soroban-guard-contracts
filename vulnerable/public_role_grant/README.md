# `vulnerable/public_role_grant`

## Vulnerability: Public Role Grant (Unauthenticated Operator Escalation)

**Severity:** Critical

## Description

A role-management contract exposes an entrypoint that grants operator powers without requiring admin authorization. Any address can call this function, immediately becoming an operator and bypassing operator-only restrictions.

## Exploit Scenario

1. Attacker calls `vulnerable_entry(attacker, amount)`.
2. Contract grants operator role to `attacker` without checking admin authorization.
3. Attacker calls `operator_only_action()` successfully.

## Vulnerable Code

See [`src/lib.rs`](src/lib.rs).

## Secure Fix

See [`src/secure.rs`](src/secure.rs).

