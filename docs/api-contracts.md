# Exported API Contracts

This document is the behavioral contract for every function exported through
the PKCS#11 2.40/3.2 function lists and the CanoKey extension header. It is a
review and implementation constraint, not a description that may drift behind
the code. Changes to an entry point must update its row, tests, and any shared
profile it relies on.

## Contract Language

Every row specifies four things:

- **Lifetime**: which caller buffers are borrowed, which data is copied, and
  which module state may outlive the call.
- **Concurrency**: which references, locks, reservations, or PC/SC operation
  guards make concurrent use safe.
- **Progress**: whether the function may block and what can cancel or drain it.
- **Exit guarantee**: the state visible after success, size query, retryable
  error, terminal error, close, logout, or finalization.

The word **must** is normative. A row may be stricter than the base PKCS#11
standard because it also captures this module's internal safety invariants.

## Shared Invariants

### Ownership and Lifetime

1. Caller pointers are borrowed only for the duration of the call unless the
   row explicitly says they are copied. No operation context may retain a
   caller pointer.
2. Persisted mechanism parameters, OAEP labels, buffered messages, context PINs,
   object templates, and secret values are module-owned copies. Sensitive
   temporary or retired storage is zeroized before reuse or release.
3. A function using `cnk_session_find()` owns one `activeCalls` reference until
   its `CNK_SESSION_REF` cleanup runs. No session or token pointer may be used
   after that reference is released.
4. A returned session-object handle is valid only in its creating session.
   Private session objects are invisible while USER is logged out.

### Lock and Reservation Order

1. `g_lifecycle_lock` serializes managed binding, initialize, finalize, and
   pending-cleanup transitions. No other module lock is acquired before it.
2. `session_mutex` protects the session table, closing tombstones, manager
   state, and reference acquisition. It may nest `token->lock` only for an
   atomic table/token transition. It must never nest `session->lock` or card
   I/O.
3. `token->lock` protects token login state, PIN/management-key caches,
   session counters, logout state, and reservation owner fields. Card I/O must
   use a reservation bit and release the mutex while transmitting.
4. `session->lock` protects find state, every cryptographic operation context,
   and session secret objects. It must not be held while acquiring
   `session_mutex`. It may nest `token->lock` when visibility or logout state
   must be rechecked before returning/using session-owned private state.
5. `token->lock` must not normally nest `session_mutex` or `session->lock`.
   The sole exception is `C_CloseSession` after its closing tombstone is
   published and `activeCalls == 1`; at that point the close reference proves
   no other thread can own `session->lock`. Any new exception requires a
   contract change and a deterministic lock-order test.
6. Reader and slot-event locks protect only reader snapshots and event queues.
   A reader name used outside the lock must be copied first.

### Output and Failure Atomicity

1. A NULL output buffer is a size query only. It must not perform irreversible
   card work or consume an operation. `CKR_BUFFER_TOO_SMALL` reports the
   required length and preserves retryable state unless the PKCS#11 standard
   explicitly requires termination.
2. Validation or host-crypto failure before card I/O leaves token and object
   state unchanged. A card mutation may be committed only while its documented
   reservation is held; a later metadata failure must not claim the mutation
   was rolled back.
3. Terminal operation calls clear and zeroize their operation context on
   success and terminal error. Size queries, `CKR_BUFFER_TOO_SMALL`, and the
   documented authentication retry preserve it.
4. Logout is token-wide. It revokes private operation contexts and queued
   private-object enumeration before clearing local credentials. If card logout
   fails, access remains fail-closed until a later retry completes.
5. Close rejects new references, drains existing references, completes token
   accounting, and only then removes/freezes the session. Any failed close
   rollback leaves counters, `closing`, caches, and table membership mutually
   consistent.
6. Finalize admits no new calls, drains session and PC/SC operations, and does
   not change allocator/binding ownership until every cleanup stage succeeds.
   Failed cleanup remains retryable with the original callbacks and allocator.

### PC/SC Card Critical Section

Managed mode supports one physical card per process. Multiple sessions and
Windows contexts may refer to that card, but a second card must not be routed
through the same process-wide token state. Card-backed PIV operations must hold
one reader transaction from connection
through the final dependent APDU. The required sequence is `connect`,
`SCardBeginTransaction`, `SELECT PIV`, all dependent APDUs, result
parse/commit, `SCardEndTransaction`, and disconnect. No helper may release the
card or select another applet between those steps. This rule covers PIN
verification plus a private operation, management-key authentication plus a
write, command chaining, and multi-step responses.

PC/SC serializes complete transactions for one physical reader, so different
sessions can issue different PIV operations without corrupting card APDUs;
they will queue at the reader. It does not protect token-wide login state,
cached PINs, management authorization, session operation contexts, or module
lifecycle. Those remain protected by the locks and reservations in the rows
below. Although the PIV standard permits a same-AID SELECT to preserve
security status, current CanoKey firmware resets PIN, PUK, and management
status in `piv_select()`. Treat every SELECT as an authorization reset and do
not select or switch applets after VERIFY until the dependent operation ends.
PKCS#11 session lifetime is a separate host concern: `C_OpenSession`,
`C_CloseSession`, and host-only operation setup/update calls must not keep a
reader transaction open. A session may span multiple card transactions, and
only the call that transmits the dependent PIV APDUs owns this critical section.

The target minidriver integration will reference-count managed contexts above
the PKCS#11 session: each `CARD_DATA` owns one session and one context
reference, while the final context performs `C_Finalize` and restores the
default binding. The current bridge already keeps allocator callbacks
process-wide and immutable, but its explicit context registry is still pending;
until then callers must not assume multi-card support.

## Profiles

| Profile | Required behavior |
| --- | --- |
| `STATIC` | No initialization requirement, no mutable token/session state, borrowed arguments only, fully concurrent. |
| `LIFECYCLE` | Serialized by `g_lifecycle_lock`; allocator, backend, session-manager, and binding transitions are transactional and retryable. |
| `SLOT-READ` | Requires initialized module and valid slot; reader/card access uses snapshot locks and a PC/SC operation guard; no login mutation. |
| `EVENT` | Owns the slot-event queue/baseline under its mutex; blocking wait is cancellable by finalization; managed mode is unsupported. |
| `SESSION` | Acquires a session reference; table mutations use `session_mutex`; no caller pointer survives the call. |
| `TOKEN-AUTH` | Uses token pending/reservation state to serialize USER/SO/logout transitions; card I/O occurs without holding `token->lock`. |
| `OP(kind)` | Holds `session->lock` for the complete API call and owns the named operation context; retained inputs are deep copies. |
| `OBJECT` | Holds `session->lock` for session objects; token objects are discovered from live PIV state; private visibility is rechecked at use/return time. |
| `CARD-WRITE` | Requires RW session and management authorization; holds token management reservation through the irreversible card call. |
| `ONE-SHOT` | Holds a session reference and token card-operation reservation through card work and result-object commit; logout cannot pass it. |
| `UNSUPPORTED` | Returns the documented unsupported/not-parallel result without allocating, retaining pointers, or changing module/session/token state. Fully concurrent. |

## Lifecycle and Interface Discovery

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_Initialize` | `LIFECYCLE` | Borrows init callbacks; a successful first call installs module-owned mutex/backend/session state. Compatible managed reentry increments one reference. | Pending cleanup is retried first with the original binding. Success publishes initialized state last; failure publishes no partially initialized module and remains retryable. |
| `C_Finalize` | `LIFECYCLE` | Borrows no state from caller. Last reference blocks new admission, drains sessions/PCSC, and destroys ownership in reverse order. | Non-last managed reference only decrements. Last success leaves fully uninitialized/default allocators. Any cleanup error preserves the original binding and a deterministic retry path. |
| `C_GetInfo` | `STATIC` | Borrows output for the call; reads immutable version/manufacturer data. | Never changes lifecycle state; returns a complete structure or argument error. |
| `C_GetFunctionList` | `STATIC` | Returns a process-lifetime pointer to immutable 2.40 function-list storage. | Does not require initialization and never returns a partial list. |
| `C_GetInterfaceList` | `STATIC` | Returns/copies immutable 3.2 interface descriptors; caller owns its array. | NULL is size query; too-small reports required count; no module state changes. |
| `C_GetInterface` | `STATIC` | Returns a process-lifetime pointer to immutable 3.2 interface storage. | Name/version/flags validation is atomic; failure leaves output unpublished. |
| `C_GetFunctionStatus` | `UNSUPPORTED` | No session lookup or retained state. | Always returns `CKR_FUNCTION_NOT_PARALLEL`. |
| `C_CancelFunction` | `UNSUPPORTED` | No session lookup or retained state. | Always returns `CKR_FUNCTION_NOT_PARALLEL`; use `C_SessionCancel` for supported cancellation. |
| `C_CNK_EnableManagedMode` | `LIFECYCLE` | Borrows card handles for the process-wide one-card binding; Windows may rotate both handles and per-context CSP allocators. PKCS#11 internal state uses the DLL allocator, while minidriver output buffers use their owning `CARD_DATA` callbacks. | Rejects standalone initialized state and incompatible cleanup-pending transitions. Success updates the active card handle without cross-heap frees. |
| `C_CNK_ResetManagedMode` | `LIFECYCLE` | Releases only an uninitialized managed binding; no caller-owned card resource is freed. | Rejects initialized or cleanup-pending state. Success restores default allocators/zero handles atomically. |
| `C_CNK_ConfigLogging` | `STATIC` | Borrows `FILE *` for the configured logging lifetime; caller must keep it valid until reconfiguration/finalization. | Logging changes are best-effort and thread-safe; no token/session/auth state changes. |

## Slot, Token, and Mechanism APIs

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_GetSlotList` | `SLOT-READ` | Caller owns list. Standalone reader snapshot is protected; managed mode exposes canonical slot 0 only. | NULL is count query; too-small reports count; `tokenPresent` filtering must not expose invalid slots. |
| `C_GetSlotInfo` | `SLOT-READ` | Borrows output; firmware/name read is guarded as one PC/SC operation. | Returns a complete snapshot; failure leaves no retained state. |
| `C_GetTokenInfo` | `SLOT-READ` | Session counters are read without reader/session lock inversion; card fields are independent snapshots. | Reports coherent open/RW counts and RNG/version flags; card-query failure does not mutate login/session state. |
| `C_GetMechanismList` | `SLOT-READ` | Algorithm-extension data is call-local; caller owns returned list. | NULL/too-small follow two-stage rules. Independently configured algorithms are advertised independently. |
| `C_GetMechanismInfo` | `SLOT-READ` | Reads call-local firmware algorithm configuration. | Returns info only for actually enabled mechanisms; no capability overclaim or state mutation. |
| `C_InitToken` | `UNSUPPORTED` | No card mutation or retained caller PIN/label. | Returns not implemented and leaves the token unchanged. |
| `C_InitPIN` | `UNSUPPORTED` | No PIN retention or card mutation. | Returns not implemented; PIN initialization is outside this module's supported PIV flow. |
| `C_SetPIN` | `TOKEN-AUTH` | Forwards borrowed old/new PINs to the PIN form of `C_CNK_SetPIN`; no PIN pointer survives. | Holds the user-operation reservation through card change and cached-PIN update. Failure does not publish a new local PIN. |
| `C_SeedRandom` | `SESSION` | Validates session and firmware RNG capability; seed bytes are borrowed and never stored. | Returns `CKR_RANDOM_SEED_NOT_SUPPORTED`; never changes token RNG state. |
| `C_GenerateRandom` | `SESSION` | Output belongs to caller; card operation is guarded and chunked. | Zero length is a no-op. Failure reports no fabricated bytes or RNG capability change. |
| `C_WaitForSlotEvent` | `EVENT` | Caller owns output slot; queue/baseline persist between calls. | Nonblocking returns one queued event or `CKR_NO_EVENT`; blocking is cancellable by finalization and never loses already queued events. |

## Session and Authentication APIs

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_OpenSession` | `SESSION` | Firmware configuration is read before `session_mutex`; new session/token counters publish atomically. | Failure publishes no handle/counter. Success returns one table-owned session with initialized lock/contexts. |
| `C_CloseSession` | `SESSION` | Sets a closing tombstone, owns a close reference, drains existing calls, then performs token accounting and cleanup. | Concurrent close gets invalid handle. Every failure restores table membership, counters, closing state, and logout barriers consistently; success invalidates handle and zeroizes secrets. |
| `C_CloseAllSessions` | `SESSION` | Iteratively snapshots one handle and delegates close without holding the table lock across cleanup/card I/O. | Completes when no matching session remains; propagates first non-stale close failure without corrupting remaining sessions. |
| `C_GetSessionInfo` | `SESSION` | Holds session reference and reads table/token state under their owning locks. | Returns one coherent state/flags/slot snapshot; never mutates login or operation state. |
| `C_GetOperationState` | `UNSUPPORTED` | Does not serialize or expose internal operation buffers. | Returns `CKR_FUNCTION_NOT_SUPPORTED` without consuming an operation. |
| `C_SetOperationState` | `UNSUPPORTED` | Does not retain serialized state/key handles. | Returns `CKR_FUNCTION_NOT_SUPPORTED` without replacing active operations. |
| `C_Login` | `TOKEN-AUTH` | Borrows PIN and delegates to `C_CNK_Login`; PIN is copied only into token/context storage defined by the selected user type. | USER/SO transitions are pending during card verification and commit atomically. Competing login/logout/reservation returns active/another-user without partial cache. |
| `C_LoginUser` | `TOKEN-AUTH` | Username must be absent; PIN lifetime is identical to `C_Login`. | Delegates only after username validation; no state change on bad username. |
| `C_Logout` | `TOKEN-AUTH` | Token-wide revoke snapshots sessions with active references, clears private operations/find queues, and zeroizes local credentials. | New private use is blocked while pending. Card logout failure remains fail-closed and retryable; success leaves PUBLIC state in every session. |
| `C_SessionCancel` | `OP(kind)` | Holds session reference/lock and cancels only requested FIND/ENCRYPT/DECRYPT/DIGEST/SIGN/VERIFY contexts. | Unsupported flags fail without cancellation. Requested contexts are zeroized atomically; unrelated operation types survive. |
| `C_CNK_Login` | `TOKEN-AUTH` | USER/SO PIN is borrowed for card verification; successful USER/SO material is copied into token-owned cache. Context-specific PIN is copied only into one unambiguous PIN-always operation. | Failed verification clears pending transition. Context login never changes token-wide login type and is consumed/zeroized by one operation or cancellation. |
| `C_CNK_LoginProtectedManagementKey` | `TOKEN-AUTH` | Borrowed management key is verified under a protected-login reservation and copied only after USER generation/state revalidation. | Logout cannot race commit. Any verification/state failure leaves management cache empty. |
| `C_CNK_LoginPinManaged` | `TOKEN-AUTH` | Temporary ADMIN/PRINTED objects and recovered key are module-owned stack buffers and always zeroized. | A USER login established by this call is rolled back on composite failure; a pre-existing USER login is preserved. |
| `C_CNK_FinalizePinManaged` | `CARD-WRITE` | Destructive PUK blocking holds token reservation across authentication, mutation, and confirmation. | Failure releases reservation then rolls back only login established by this call. Success guarantees PUK retry count is zero and PIN-managed auth is usable. |
| `C_CNK_SetPIN` | `TOKEN-AUTH` | Borrowed PIN/PUK buffers exist only through the reserved card operation; tries output is caller-owned. | Card mutation and matching cache update commit as one logical transition. Other login/logout/write transitions cannot pass it. |
| `C_CNK_UnblockPIN` | `TOKEN-AUTH` | Borrowed PUK/new PIN are never retained beyond the reserved card operation. | Success updates USER cache only according to documented login state; failure preserves old local credentials and reports retries. |

## Object APIs

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_CreateObject` | `OBJECT` / `CARD-WRITE` | Template is borrowed. Session-secret data is copied under `session->lock`; PIV private/certificate/data writes hold management reservation and zeroize import buffers. | Session object publishes only after full template validation. Card write failure returns no handle; a committed card mutation is never represented as rolled back. |
| `C_CopyObject` | `OBJECT` | Source session secret is snapshotted under `session->lock`; copied value is module-owned and zeroized after allocation. | Only copyable visible session secrets succeed. Failure publishes no new handle and leaves source unchanged. |
| `C_DestroyObject` | `OBJECT` | Holds `session->lock`; secret bytes are zeroized before handle becomes inactive. | Private visibility and destroyable policy are rechecked. PIV token objects remain unchanged and return action prohibited. |
| `C_GetObjectSize` | `OBJECT` | Uses ordinary attribute APIs; no returned pointer is retained. | Returns a coherent estimated object size or error; no object/operation state mutation. |
| `C_GetAttributeValue` | `OBJECT` | Session secrets are read under `session->lock`; private visibility is checked at call time. Token attributes use call-local metadata/certificate buffers. | Per-attribute unavailable/sensitive errors follow PKCS#11 rules. Size query is non-consuming; malformed card TLV never causes partial out-of-bounds copy. |
| `C_SetAttributeValue` | `OBJECT` | Mutable session-secret changes apply to a temporary snapshot under `session->lock`; template pointers are borrowed. | All attributes validate before commit. PIV token attributes are read-only; failure leaves the live secret unchanged. |
| `C_FindObjectsInit` | `OP(FIND)` | Template is consumed during the call; result handles are copied into session-owned find state under `session->lock`. | Success starts exactly one find operation. Failure clears partial results. Private visibility is evaluated before queuing. |
| `C_FindObjects` | `OP(FIND)` | Returns handles from session-owned queue while holding `session->lock`; token logout barrier is rechecked before return. | Returns at most requested count and advances position once. Logout invalidates queued private results; failure does not leak a private handle. |
| `C_FindObjectsFinal` | `OP(FIND)` | Owns no caller data; clears session find state under lock. | Success/terminal failure leaves no active find operation and no queued handles. |
| `C_CNK_GetPivData` | `SESSION` | Tag/output are borrowed; returned bytes belong to caller. Private reads may use a copied cached PIN for that card transaction only. | NULL output is size query. Logout/pending auth blocks private access; card/parse failure leaves token state unchanged. |
| `C_CNK_ObjIdToPivTag` | `STATIC` | Pure fixed-table mapping; output belongs to caller. | Valid ID writes exactly one tag; invalid ID leaves no module state and returns object-handle error. |

## Encrypt and Decrypt APIs

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_EncryptInit` | `OP(ENCRYPT)` | Public key/metadata and mechanism parameters are copied into session encrypt context under lock. | Publishes context only after full validation; active operation is not overwritten on error. |
| `C_Encrypt` | `OP(ENCRYPT)` | Input/output borrowed for call; host RSA temporaries are zeroized. | NULL/too-small preserves context and reports size. Real success or terminal error clears context; no card/private state is used. |
| `C_EncryptUpdate` | `UNSUPPORTED` | Does not read or change encrypt context. | Returns `CKR_FUNCTION_NOT_SUPPORTED`; existing single-part context remains unchanged. |
| `C_EncryptFinal` | `UNSUPPORTED` | Does not read or change encrypt context. | Returns `CKR_FUNCTION_NOT_SUPPORTED`; existing single-part context remains unchanged. |
| `C_DecryptInit` | `OP(DECRYPT)` | Mechanism/OAEP label and key metadata are copied into session decrypt context; context PIN storage starts empty. | Publishes only after key/mechanism/policy validation. Existing operation returns active unchanged. |
| `C_Decrypt` | `OP(DECRYPT)` | Ciphertext/output borrowed; raw RSA and context PIN temporaries are module-owned/zeroized. Card call uses PC/SC guard. | NULL/too-small and auth-required preserve retryable context. Success/terminal error consumes context; logout/cancel cannot free it while call holds lock. |
| `C_DecryptUpdate` | `UNSUPPORTED` | Does not read or change decrypt context. | Returns `CKR_FUNCTION_NOT_SUPPORTED`; existing single-part context remains unchanged. |
| `C_DecryptFinal` | `UNSUPPORTED` | Does not read or change decrypt context. | Returns `CKR_FUNCTION_NOT_SUPPORTED`; existing single-part context remains unchanged. |

## Digest APIs

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_DigestInit` | `OP(DIGEST)` | Creates module-owned hash context under `session->lock`; mechanism pointer is not retained. | Publishes active context only after setup/start succeeds; does not replace another digest. |
| `C_Digest` | `OP(DIGEST)` | Data/output are borrowed for call. | NULL/too-small preserves digest. Real success consumes it; invalid input or hash failure resets/zeroizes it. |
| `C_DigestUpdate` | `OP(DIGEST)` | Part is borrowed and processed while holding `session->lock`. | Success advances exactly once. Backend failure terminates/reset context; bad NULL input performs no update. |
| `C_DigestKey` | `OP(DIGEST)` / `OBJECT` | Reads a visible session secret under the same session lock; key bytes never leave module. | Sensitive/non-extractable/private-hidden keys are rejected before update. Hash failure resets digest. |
| `C_DigestFinal` | `OP(DIGEST)` | Output is caller-owned; hash context remains module-owned. | NULL/too-small preserves context. Real success or hash failure resets it. |

## Sign and Verify APIs

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_SignInit` | `OP(SIGN)` | Mechanism parameters, metadata, public modulus, and multipart hash/message state become module-owned copies. | Publishes only after key/mechanism/policy validation. PIN-always starts unauthenticated and requires one context login. |
| `C_Sign` | `OP(SIGN)` | Data/output borrowed; context PIN and signature temporaries are zeroized/consumed by real card operation. | NULL/too-small/auth-required preserve context. Success/terminal error clears it; context PIN authorizes only this operation. |
| `C_SignUpdate` | `OP(SIGN)` | Part is copied/hashed into module-owned multipart state under lock. | Success advances once; allocation/hash failure terminates as documented and leaves no partial exposed buffer. |
| `C_SignFinal` | `OP(SIGN)` | Output is caller-owned; buffered message/hash remains module-owned until terminal call. | NULL/too-small/auth-required preserves state. Success/terminal error clears and zeroizes it. |
| `C_SignRecoverInit` | `UNSUPPORTED` | Does not allocate or alter sign state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_SignRecover` | `UNSUPPORTED` | Does not consume input or existing sign state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_VerifyInit` | `OP(VERIFY)` | Mechanism, public key, and independent hash/message state are module-owned copies. | Publishes only after validation; may coexist with standalone DIGEST. |
| `C_Verify` | `OP(VERIFY)` | Data/signature borrowed; host crypto temporaries are zeroized. | Success/signature-invalid/terminal error clears context; argument/size semantics do not corrupt other operations. |
| `C_VerifyUpdate` | `OP(VERIFY)` | Part is copied/hashed under session lock. | Success advances once; failure terminates only VERIFY state. |
| `C_VerifyFinal` | `OP(VERIFY)` | Signature borrowed for terminal host verification. | Always clears VERIFY state after a real verification result; unrelated operations survive. |
| `C_VerifyRecoverInit` | `UNSUPPORTED` | Does not allocate or alter verify state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_VerifyRecover` | `UNSUPPORTED` | Does not consume input or existing verify state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |

## Key Creation, Agreement, and Combined Operations

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_DigestEncryptUpdate` | `UNSUPPORTED` | Does not change DIGEST or ENCRYPT state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_DecryptDigestUpdate` | `UNSUPPORTED` | Does not change DECRYPT or DIGEST state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_SignEncryptUpdate` | `UNSUPPORTED` | Does not change SIGN or ENCRYPT state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_DecryptVerifyUpdate` | `UNSUPPORTED` | Does not change DECRYPT or VERIFY state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_GenerateKey` | `OBJECT` | Template is borrowed; random secret prototype is stack-owned and zeroized; final secret is copied under `session->lock`. | Private result requires current USER visibility. Failure publishes no handle and no residual random key. |
| `C_GenerateKeyPair` | `CARD-WRITE` | Templates borrowed; generated public-key buffer call-local. Management reservation spans irreversible generation. | Success publishes deterministic PIV handles after card commit. Failure before/at card call publishes neither handle; no partial local object exists. |
| `C_WrapKey` | `UNSUPPORTED` | Does not read secret value or alter operation state. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_UnwrapKey` | `UNSUPPORTED` | Does not retain wrapped data/template or create an object. | Returns `CKR_FUNCTION_NOT_SUPPORTED`. |
| `C_DeriveKey` | `ONE-SHOT` | Peer/KDF/template borrowed; raw/KDF secrets and prototype are zeroized. Reservation spans card ECDH through session-secret commit. | PIN-always fails closed. Success publishes one session-secret handle; any failure publishes none and logout cannot pass mid-call. |
| `C_EncapsulateKey` | `OBJECT` | Public key/template borrowed; host ML-KEM secrets/prototype are zeroized; final secret copied under session lock. | NULL/too-small ciphertext is non-consuming and publishes invalid/no key. Real success publishes ciphertext and one key together. |
| `C_DecapsulateKey` | `ONE-SHOT` | Ciphertext/template borrowed; raw secret/prototype zeroized. Reservation spans card ML-KEM through session-secret commit. | PIN-always fails closed. Success publishes one key; failure publishes none and logout cannot pass mid-call. |

## PKCS#11 3.x Message, Async, and Authenticated APIs

Except for `C_LoginUser`, `C_SessionCancel`, `C_EncapsulateKey`, and
`C_DecapsulateKey`, the following 3.x entries are signature-correct stubs. A
stub must remain state-neutral even when another classic operation is active.

| API | Profile | Lifetime and concurrency | Progress and exit guarantee |
| --- | --- | --- | --- |
| `C_MessageEncryptInit` | `UNSUPPORTED` | Retains no mechanism/key. | Returns `CKR_FUNCTION_NOT_SUPPORTED`; classic ENCRYPT state unchanged. |
| `C_EncryptMessage` | `UNSUPPORTED` | Retains no parameters/AAD/plaintext. | Returns unsupported; writes no ciphertext/length and changes no state. |
| `C_EncryptMessageBegin` | `UNSUPPORTED` | Retains no parameters/AAD. | Returns unsupported; creates no message operation. |
| `C_EncryptMessageNext` | `UNSUPPORTED` | Retains no parameters/plaintext. | Returns unsupported; writes no output and advances no state. |
| `C_MessageEncryptFinal` | `UNSUPPORTED` | Owns no message state. | Returns unsupported; classic ENCRYPT state unchanged. |
| `C_MessageDecryptInit` | `UNSUPPORTED` | Retains no mechanism/key. | Returns unsupported; classic DECRYPT state unchanged. |
| `C_DecryptMessage` | `UNSUPPORTED` | Retains no parameters/AAD/ciphertext. | Returns unsupported; writes no plaintext/length and changes no state. |
| `C_DecryptMessageBegin` | `UNSUPPORTED` | Retains no parameters/AAD. | Returns unsupported; creates no message operation. |
| `C_DecryptMessageNext` | `UNSUPPORTED` | Retains no parameters/ciphertext. | Returns unsupported; writes no output and advances no state. |
| `C_MessageDecryptFinal` | `UNSUPPORTED` | Owns no message state. | Returns unsupported; classic DECRYPT state unchanged. |
| `C_MessageSignInit` | `UNSUPPORTED` | Retains no mechanism/key. | Returns unsupported; classic SIGN state unchanged. |
| `C_SignMessage` | `UNSUPPORTED` | Retains no parameters/data. | Returns unsupported; writes no signature/length and changes no state. |
| `C_SignMessageBegin` | `UNSUPPORTED` | Retains no parameters. | Returns unsupported; creates no message operation. |
| `C_SignMessageNext` | `UNSUPPORTED` | Retains no parameters/data. | Returns unsupported; writes no signature and advances no state. |
| `C_MessageSignFinal` | `UNSUPPORTED` | Owns no message state. | Returns unsupported; classic SIGN state unchanged. |
| `C_MessageVerifyInit` | `UNSUPPORTED` | Retains no mechanism/key. | Returns unsupported; classic VERIFY state unchanged. |
| `C_VerifyMessage` | `UNSUPPORTED` | Retains no parameters/data/signature. | Returns unsupported and changes no state. |
| `C_VerifyMessageBegin` | `UNSUPPORTED` | Retains no parameters. | Returns unsupported; creates no message operation. |
| `C_VerifyMessageNext` | `UNSUPPORTED` | Retains no parameters/data/signature. | Returns unsupported and advances no state. |
| `C_MessageVerifyFinal` | `UNSUPPORTED` | Owns no message state. | Returns unsupported; classic VERIFY state unchanged. |
| `C_VerifySignatureInit` | `UNSUPPORTED` | Retains no mechanism/key/signature. | Returns unsupported; classic VERIFY state unchanged. |
| `C_VerifySignature` | `UNSUPPORTED` | Retains no data. | Returns unsupported and advances no state. |
| `C_VerifySignatureUpdate` | `UNSUPPORTED` | Retains no data part. | Returns unsupported and advances no state. |
| `C_VerifySignatureFinal` | `UNSUPPORTED` | Owns no message state. | Returns unsupported; classic VERIFY state unchanged. |
| `C_GetSessionValidationFlags` | `UNSUPPORTED` | Does not acquire/alter validation state. | Returns unsupported and does not publish flags. |
| `C_AsyncComplete` | `UNSUPPORTED` | Retains no function name/result pointer. | Returns unsupported; no async state exists. |
| `C_AsyncGetID` | `UNSUPPORTED` | Retains no function name. | Returns unsupported and publishes no ID. |
| `C_AsyncJoin` | `UNSUPPORTED` | Retains no function name/data. | Returns unsupported; never blocks waiting for an async operation. |
| `C_WrapKeyAuthenticated` | `UNSUPPORTED` | Retains no mechanism/key/AAD and reads no key material. | Returns unsupported; writes no wrapped output and changes no state. |
| `C_UnwrapKeyAuthenticated` | `UNSUPPORTED` | Retains no wrapped data/template/AAD. | Returns unsupported; creates no object and changes no state. |

## Review Checklist Per Entry Point

For any implementation or review, answer all of these against the API row:

1. Which caller pointers, handles, and callbacks are borrowed, copied, or
   returned, and when does each lifetime end?
2. Which mutable state can this function read or write? Name the owning lock or
   reservation for every item.
3. Can it run concurrently with itself, close, logout, cancellation, finalize,
   reader refresh, and a different operation type? If yes, identify the
   linearization point. If no, identify the returned error or wait condition.
4. Where can the call block? Which counter/reference makes finalization wait,
   and which cancellation path wakes it?
5. For every return after state mutation, is the state committed, retryable, or
   rolled back? Are counters, pending flags, owners, handles, and caches still
   mutually consistent?
6. Are all sensitive buffers zeroized on every early return, including template
   validation and policy rejection?
7. Does a size query or `CKR_BUFFER_TOO_SMALL` avoid card work and preserve the
   exact state needed for retry?

`scripts/check-api-contracts.py` enforces inventory completeness. It does not
prove semantic conformance; unit tests, sanitizer tests, failure injection, and
cold review must verify the contracts themselves.
