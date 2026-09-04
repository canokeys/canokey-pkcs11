# CanoKey PKCS#11 Architecture

`docs/api-contracts.md` is the normative ownership, concurrency, progress, and
exit-state specification for every exported entry point. This document explains
the larger component boundaries; implementation and review must satisfy both.

## Layers

The module has four internal layers:

1. Public PKCS#11 and CanoKey extension declarations live in `include/`.
2. Entry points and PKCS#11 state machines live in `src/api/`.
3. Reusable encoding and cryptographic helpers live in `src/internal/`.
4. PC/SC transport and PIV commands live in `src/backend/`.

`src/api/core.c` owns initialization and the 2.40/3.2 function tables.
`session.c` owns session handles and token-scoped authentication.
`operation.c` is the single cleanup boundary for digest, sign, verify, encrypt,
and decrypt contexts. `object.c` owns PKCS#11 object discovery and attributes;
PIV import wire encoding is isolated in `internal/piv_object.c`, and generic
template decoding is isolated in `internal/template.c`.

`backend/piv_metadata.c` owns PIV version gates, metadata discovery, algorithm
extensions, PIN/PUK retry metadata, permanent PUK blocking, and token
randomness. `backend/piv_crypto.c` owns card-backed private-key operations and
key generation/import. `backend/piv_auth.c` owns PIN, PUK, and management-key
authentication. `backend/piv_data.c` owns PIV data objects and legacy
version/serial commands. `backend/pcsc.c` is limited to reader discovery, slot
events, transaction ownership, and APDU transport. These focused modules share
transaction helpers so managed mode continues to use the minidriver's card
handle and every operation balances `SCardBeginTransaction` with
`cnk_disconnect_card`.

## PC/SC Transaction Boundary

Every actual card-backed PIV operation is one contiguous critical section. This
is not the lifetime of a PKCS#11 session:

```text
connect card -> SCardBeginTransaction -> SELECT PIV -> all dependent APDUs
-> parse/commit the result -> SCardEndTransaction -> disconnect card
```

The card must not be released between SELECT and the final APDU. This applies
to command chaining, PIN verification followed by a private operation, key
generation/import, management-key authentication, and multi-step PIV responses.
Internal helpers should make the selected-PIV transaction explicit so callers
cannot accidentally transmit an operation after returning the card to PC/SC.

PC/SC serializes complete physical card transactions in a reader. Two PKCS#11
sessions may therefore request a PIV signature and a PIV decrypt concurrently;
their card transactions queue at the reader, while host-only work and their
independent session contexts can still run concurrently. This physical
serialization does not replace `token->lock`, session locks, token
reservations, or lifecycle admission: login/logout, PIN caches, management
authorization, operation contexts, and finalization remain shared host state.

`C_OpenSession`, `C_CloseSession`, `C_Login`, and operation `Init`/`Update`
calls may only change host state and do not reserve a card transaction unless
their implementation actually needs an APDU. A session may outlive many card
transactions, and a multipart PKCS#11 operation may buffer data in the host
until its card-facing final step. Holding a PC/SC transaction from
`C_OpenSession` to `C_CloseSession` would unnecessarily block other sessions
and would make reader removal and cancellation harder to recover.

The PIV standard permits selecting the same PIV application again without
changing PIV security status, but the current CanoKey firmware deliberately
resets `pin.is_validated`, PUK status, and management status in `piv_select()`.
Therefore this backend must treat every PIV SELECT as an authorization reset:
SELECT must precede VERIFY, and no SELECT or applet switch may occur after
VERIFY before the dependent operation completes. This firmware behavior is
tested as a product invariant even though it is stricter than the standard.

## State Ownership

Authentication is token-scoped, not session-scoped. One
`CNK_PKCS11_TOKEN_STATE` per slot owns the USER PIN cache, management-key cache,
login role, and session counters. Its lock protects all of those fields.

Each `CNK_PKCS11_SESSION` owns active operation contexts, copied mechanism
parameters, bounded multipart buffers, session-only secret keys, and find
state. It references, but does not own, token authentication state.

Session lookup acquires an active-call reference protected by the global
session-table mutex. Close publishes a tombstone, keeps its own active-call
reference visible to finalization, drains existing calls, completes token
accounting and operation cleanup, and only then removes the handle. A session
whose application mutex destroy callback fails is retained for cleanup retry.
Close never acquires a session lock while holding the global lock.
Closing the last session and `C_Finalize` also zero the USER PIN and
management-key caches owned by `CNK_PKCS11_TOKEN_STATE`.

Digest, Sign, Verify, Encrypt, and Decrypt state is protected by the per-session
lock for the complete API call. Cancellation uses the same lock. Combined-hash
Sign and Verify own embedded hash contexts, so either can coexist with the
session's independent Digest operation.

USER and SO authentication use token-lock-protected pending states while their
card verification is in flight. Read-only session creation checks and updates
the SO/read-only counters in the same token critical section.

PIN-managed management-key login requires both the ADMIN DATA policy bits and
an actually blocked PUK. `C_CNK_FinalizePinManaged` is the explicit destructive
provisioning boundary that authenticates USER and management authority before
driving PUK retries to zero; ordinary login never mutates retry counters.

## Card And Host Responsibilities

The card performs operations that require private or token-resident material:

- USER and management-key authentication;
- PIV key generation/import and data-object writes;
- private-key sign, RSA decrypt, ECDH, and ML-KEM decapsulation;
- firmware 6.0+ random generation.

The host performs public or transient operations:

- RSA/ECDSA/ML-DSA verification and RSA public-key encryption;
- hashing, RSA padding, OAEP, PSS verification, and X9.63 KDF;
- ML-KEM encapsulation;
- session AES/generic-secret generation and object lifecycle.

Mixed mechanisms do not advertise `CKF_HW`, because that flag would claim that
every operation represented by the mechanism is hardware-backed.

## Object Model

PIV key and certificate handles encode slot, class, and a fixed object ID.
Object IDs `1..24` map to PIV key slots `9A`, `9C`, `9D`, `9E`, and `82..95`.
Session secret IDs start at `0x80`, outside that range.

PIV token objects are live views of card metadata and data objects. They are
not copied or deleted by PKCS#11. Session secret objects are host-resident and
support copy, secure destroy, restricted metadata updates, and digest when not
sensitive.

PIV private-key visibility follows the stored PIN policy. PIN-never keys are
public PKCS#11 objects (`CKA_PRIVATE=false`) so callers can discover and use
them without authentication. PIN-once and PIN-always keys are private objects
and are omitted from public-session searches; USER login makes them visible.

## Firmware Gates

- PIV 5.7+ provides the metadata directory and runtime PQ algorithm IDs.
- PIV 6.0+ provides unauthenticated token randomness through `00 84`.

Older firmware uses per-slot probes, does not advertise PQ mechanisms, and
does not set `CKF_RNG`.

Standalone reader names retain stable slot IDs for one initialized module
lifetime. PnP refresh compares old and new reader sets so removal reports the
removed slot, including removal of the final reader.

## Variable-Length Operations

Length queries and `CKR_BUFFER_TOO_SMALL` preserve active Sign, Digest,
Encrypt, and Decrypt operations so callers can retry. Successful final calls,
signature mismatch, cancellation, and non-retryable errors consume their
operation context. OAEP labels and other mechanism parameters are copied at
Init time and never borrow caller memory.

## Verification

Use both build shapes:

```powershell
cmake --build build-ninja-clangcl-x64
cmake --build build-real-ninja-clangcl-x64
```

`test_real.exe` covers established classic PIV paths. `test_pqc.exe` covers
function-table completeness, sessions/login, session-secret lifecycle, random
generation, PQ operations, host Verify/Encrypt, and retry/cancellation behavior
on current hardware. Its function-table check requires every
`CK_FUNCTION_LIST_3_2` entry declared by `pkcs11f.h` to be non-NULL; unsupported
entries are populated by `core.c` with type-correct stubs. It requires an
explicit slot ID and serial; destructive key writes additionally require
`CNK_RUN_DESTRUCTIVE_REAL_TESTS=1`.

## Remaining Structural Work

The current large files still have identifiable future boundaries:

- `api/object.c`: separate enumeration/handle validation from class-specific
  attribute readers. Wire encoding has already moved out.
- `api/sign.c`: separate Verify after extracting one shared signature-mechanism
  descriptor layer; splitting first would duplicate RSA/ECDSA mechanism rules.
- `api/slot.c` and signature/encryption dispatch: converge mechanism lists,
  flags, key sizes, and dispatch validation on one descriptor table.

These are ownership-driven splits. File length alone is not a reason to create
another module or expose a formerly static helper.
