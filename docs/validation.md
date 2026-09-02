# Review and Validation Standard

This document is mandatory for changes that affect PKCS#11 state, card I/O,
cryptographic operations, or the Windows minidriver integration. A successful
build is not sufficient evidence of correctness.

Start with the affected rows in `docs/api-contracts.md`. Each exported API row
defines its pointer lifetime, owned state, synchronization, progress, and exit
guarantee. If a change cannot be described by the existing row/profile, update
the contract before changing code. Run `python scripts/check-api-contracts.py`
to verify that the exported inventory remains complete.

## State Invariants

Review the token state as a state machine. The relevant states are `PUBLIC`,
`USER`, `SO`, `TOKEN_LOGIN_PENDING_USER`, `TOKEN_LOGIN_PENDING_SO`,
`managementLoginPending`, `managementOperationPending`, and `logoutPending`.

- PIN-managed login remains `USER` while the protected management key is cached.
- `SO` login and PIN-managed management-key authorization are distinct valid
  write authorizations.
- Logout must block new login, private operations, management writes, and
  destructive provisioning until card logout and local cache cleanup finish.
- PIN change/unblock and PIN-managed finalize are card mutations too; they must
  reserve the token operation and cannot repopulate credentials after logout.
- Every pending flag has a success, card-error, and mutex-error exit that
  returns the token to a usable, non-authorized state.
- Every session reference is released even when an application mutex callback
  fails. Every operation context and secret buffer is cleared on close/cancel.
- Managed mode cannot replace an initialized standalone binding or silently
  switch card/allocator bindings.

Before editing, write the affected transitions down and identify the operation
that owns each reservation. Do not infer authorization from a single enum or
from the presence of a cached credential.

## Required Test Matrix

For every changed authorization or card-write path, cover these combinations:

| Operation | PUBLIC | USER | USER + protected management key | SO | Logout/finalize race |
| --- | --- | --- | --- | --- | --- |
| Read public metadata | pass | pass | pass | pass | blocked only during teardown |
| Private crypto | reject or policy-defined | pass when PIN policy allows | pass | policy-defined | reject |
| PIV write/key generation | reject | reject without protected key | pass | pass | reject |
| PIN-managed finalize | reject | pass with reservation | pass only if explicitly supported | reject unless specified | serialized |

Also test session close during each operation, multiple sessions on one token,
concurrent operations of different types, and that managed sessions reject any
slot ID other than canonical slot 0 while `C_GetSlotList` returns only slot 0.

`C_DeriveKey` is a one-shot API with no context-specific login boundary. A
PIN-always PIV ECDH key therefore fails closed with `CKR_USER_NOT_LOGGED_IN`
until a dedicated context-authentication channel is defined; it must never use
the token-wide USER PIN cache as a substitute.

The same fail-closed rule applies to ML-KEM decapsulation. One-shot ECDH and
ML-KEM private operations reserve the token operation slot until the card call
and session-secret commit complete, so logout cannot clear authorization or
release the card transaction underneath them. Private session secrets are
hidden unless a USER login is currently cached.

## Card Transaction Validation

Review every actual card-backed path as a single transaction boundary. Do not
confuse this with a PKCS#11 session boundary:

```text
connect -> begin transaction -> SELECT PIV -> dependent APDUs -> commit/parse
-> end transaction -> disconnect
```

Add a regression test for each multi-APDU path that proves the card is not
released between SELECT and its final APDU. Include PIN verification followed
by sign/decrypt/derive, management-key authentication followed by a write, and
chained GENERAL AUTHENTICATE. A second session may start a different PIV
operation, but it must wait for the first physical card transaction; the test
must also verify that host session state remains independent.

`C_OpenSession`/`C_CloseSession` and host-only `Init`/`Update` calls must not
hold a PC/SC transaction open. A session can span multiple card transactions;
only the API call that transmits PIV APDUs owns the connect-to-disconnect card
critical section.

Do not use PC/SC serialization as a substitute for host synchronization. Token
login/logout, cached credentials, management reservations, session operation
contexts, and finalization still require their documented locks and admission
guards. The PIV standard permits a same-AID reselect to preserve security
status, but current CanoKey firmware resets PIN/PUK/management status in its
PIV SELECT handler. Treat SELECT as an authorization reset: test that SELECT
comes before VERIFY and that no later SELECT/app-switch occurs before the
dependent operation. Keep a separate internal VERIFY-only path for an already
selected transaction.

## Failure Injection

Application mutex callbacks must be tested with failure injected at every lock
site relevant to the change: first call, middle call, final reacquisition, and
permanent failure. Assert all of the following after each failure:

- no pending flag is stranded;
- login state and token counters are unchanged or deliberately rolled back;
- `C_CloseSession` terminates and does not spin;
- no stale PIN or management key remains usable;
- backend mutexes and PC/SC state are either fully alive or fully released;
- a subsequent initialize/finalize retry has a deterministic result.
- finalization does not free a session or token while `activeCalls` is nonzero.
- finalization waits for the PC/SC operation counter to reach zero before
  releasing the context used by `SCardTransmit`.

## Cross-Repository Checks

When the minidriver submodule changes, validate PKCS#11 and minidriver together.
Check card handle, allocator, session, and object ownership across
`CardAcquireContext`/`CardDeleteContext`. Verify that the six Windows containers
remain limited to `9A`, `9C`, `9D`, `9E`, `82`, and `83` unless the product policy
explicitly changes.

Run, at minimum:

```text
PKCS#11: Linux unit tests
PKCS#11: ASan/UBSan with leak detection
PKCS#11: Windows ClangCL build
Minidriver: Windows Ninja/ClangCL build
Minidriver: API-level key/sign/decrypt/derive tests when hardware is available
```

Hardware and destructive tests must identify the reader/card explicitly and
must never be treated as substitutes for deterministic unit tests.

## Review Procedure

1. Read the current AGENTS.md files and the complete diff from the relevant
   base, including submodule changes.
2. Reproduce each existing review finding with a regression test before fixing
   it where practical.
3. Perform a cold review from API contracts, state transitions, lock ordering,
   cleanup ownership, and sensitive-data lifetime; use text/AST searches for
   every caller of changed helpers.
4. Run the complete required matrix and sanitizer suite.
5. Request Copilot and CodeRabbit full reviews against the final commit, then
   verify that their review range includes that commit. Resolve every actionable
   comment or document why it is invalid.
6. Repeat steps 2-5 after each non-trivial fix. Record residual architectural
   limitations explicitly instead of silently relying on a mitigation.
