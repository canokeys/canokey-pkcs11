# CanoKey PKCS#11 architecture

[api-contracts.md](api-contracts.md) specifies exported API lifetime, concurrency
and exit guarantees. [The migration plan](libcanokey-piv-migration-plan.md) records
current adaptation and remaining acceptance gates.

## Modules and ownership

| Module | Responsibility |
| --- | --- |
| include/ | Public PKCS#11 and CanoKey declarations |
| api/core.c | Initialization and complete, type-correct 2.40/3.2 function tables |
| api/session.c | Session handles, active references and token authentication |
| api/operation.c | Shared operation cleanup and cancellation |
| api/object.c | PKCS#11 discovery, attributes and object handles |
| api/container_name.c | F5 extension's CK_RV/version policy and reservations |
| internal/template.c, piv_object.c | PKCS#11 template validation and typed import views |
| internal/crypto.c and crypto helpers | Host hashing, padding, KDF and public-key crypto |
| backend/pcsc.c | Reader/slot lifecycle, transaction ownership and raw transport |
| backend/piv_operation.c | Borrowed profile construction, bounded Rust executor, error mapping and public-key compatibility |
| backend/piv_metadata.c | Public snapshots and typed version/configuration/retry/RNG operations |
| backend/piv_auth.c | Credential/cache integration using Rust credential and management operations |
| backend/piv_crypto.c, piv_data.c | Typed private/key/data/certificate operations and compatibility adapters |
| backend/piv_key_write.c | Fresh managed-slot occupancy guard |
| rust/lib.rs | Static linkage of the libcanokey C ABI |

Libcanokey owns APDU conversations, framing, parsing, typed errors and
zeroizing temporary copies. C owns raw PC/SC exchange, PKCS#11 state, returned buffers and
credential/reservation lifetime. Rust receives no connection lease or mutable
application state. It performs no I/O except through caller-driven exchanges.

Private-key import passes semantic parameters and borrowed component views to the
Rust constructor. C retains RSA template-width admission and one padded EC scalar;
that descriptor cannot be copied because its view points inside it. The descriptor
is wiped on every exit, and the Rust operation owns/wipes its copies. There is no
C import TLV encode/reparse or certificate framing. Management-protection data
is decoded by Rust: stored flags remain claims,
malformed data cannot become unconfigured success, and PRINTED yields a validated,
zeroizing 24-byte key copy. One Rust operation also validates live PUK state,
verifies the recovered key and optionally finalizes PUK blocking. C owns logical
USER/SO transitions, reservations and protected-cache commit.
Backend preflight consults the Rust profile before authentication. C uses semantic
algorithms throughout; configured wire IDs remain inside Rust. Mechanism list/info
share a profile capability projection, including message limits. The duplicate
algorithm-configuration cache is removed; reader events invalidate the profile by
generation. Certificate adapters take PIV slots directly without tag roundtrips.
F5 similarly delegates its command and UTF-16 validation to Rust; [container-names.md](container-names.md)
defines the consumer's precise fallback and error mapping.

## Transactions and shared state

A card operation owns one contiguous transaction:

```text
connect -> begin -> SELECT PIV -> authenticate if needed -> dependent APDUs
-> parse/commit -> end -> disconnect (standalone) or retain caller handle (managed)
```

CanoKey 2.0+ clears PIN/PUK/management authorization on SELECT, including
same-AID selection (1.6.2 retained it). A raw current-card check in one PC/SC
transaction confirmed PIN status 9000 -> 63C3 and protected access 9000 -> 6982
on re-SELECT. Probe before authentication; never reselect between authentication
and its target. Ordinary factories use CNK_PIV_USE_EXISTING here, with no
separate context handle. Command/result getters never advance. The bounded
executor owns scratch; callers free operations on every exit.

A session can span many transactions. Open/close and host-only Init/Update calls
must not hold a transaction for the session's lifetime. PC/SC serializes physical
I/O; it does not replace session locks, token reservations or lifecycle admission.

One CNK_PKCS11_TOKEN_STATE per slot owns login role, USER PIN, management-key cache,
session counters and immutable profile. Its lock protects publication and synchronous factory construction.
Binding epochs prevent stale profile publication; finalization drains active calls
before invalidation/free and PC/SC release. Each session owns operation contexts,
copied parameters, multipart buffers, session secrets and find state.

Session lookup acquires an active reference. Close publishes a tombstone, drains
calls, cleans operations/token accounting and only then removes the handle. Failed
application-mutex destruction retains the object for cleanup retry. Never acquire
a session lock while holding the global table lock. Last close/finalize wipe
credential caches. Cancellation uses the same session lock as normal operations.

A token reservation admits card work. Logout revokes non-admitted work; admitted
work retains authorization through I/O and result commit. Managed key writes also
require fresh, explicit empty-slot metadata in the same authenticated transaction.
Occupied/unknown slots block replacement; standalone provisioning retains explicit
replacement behavior. Dropping a Rust operation is not card rollback. Uncertain
mutations invalidate public snapshots before transaction release.

## Public snapshots and object model

Public-key snapshots contain owned modulus/exponent, EC point or raw key bytes.
Rust validates their card representation once; C no longer encodes and reparses
public-key TLVs. Generation validates its Rust result and publishes handles only.
PKCS#11 CKA_EC_POINT DER wrapping remains a host attribute responsibility.

The standalone public cache holds only directory entries, key metadata and
certificate bytes. Every read checks the 60-second TTL and metadata_cache /
CNK_PIV_METADATA_CACHE controls. Managed mode bypasses it. Credentials, handles,
selected applets and authentication state never enter the cache. Atomic invalidation
generations prevent old reads from repopulating a cleared snapshot, including
failed application-lock callbacks. Configuration cache publication also retains
the binding epoch captured before I/O. Profiles refresh after 60 seconds and keep
the previous immutable value available to already admitted transactions until
a replacement is published; refresh errors propagate.

PIV handles encode slot, class and object ID; IDs 1..24 map to 9A/9C/9D/9E/82..95.
Session-secret IDs start at 0x80. PIV objects are live views: certificate deletion
is supported, but generic key/data deletion and token-object copying are not.
Session secrets support copy, secure destruction and policy-limited metadata/digest.
PIN-never keys are public objects (CKA_PRIVATE=false); PIN-once/always private
objects become visible after USER login.

NULL/short output preserves active digest/sign/encrypt/decrypt operations.
RSA decrypt preflight reports the mechanism's conservative bound (modulus bytes,
minus padding overhead where applicable) before card I/O; retries must provide
that capacity, including when the actual padded plaintext is shorter. Success,
terminal error, signature mismatch and cancellation consume their contexts. Init
copies mechanism parameters, including OAEP labels. PIN-always sign/decrypt use an
operation-local context PIN; derive/decapsulation remain fail-closed without a
dedicated context-authentication boundary.

Raw CKO_DATA consumers retain container framing. Certificates expose the decoded,
optionally decompressed payload. P-521 accepts definite BER response envelopes but
strict DER signatures, and normalizes digest length exactly once. Firmware support
uses observed profiles, distinguishes unknown from unsupported, and preserves the
original development-version identity while using its declared base version.
RNG checks the live PIV version before producing bytes; F5 retains its PIV 6.0
consumer gate. Logical session opening performs no card I/O and stores no algorithm mapping.
Host policy uses semantic algorithm codes; card operations preflight support and
encode wire identifiers through the same immutable Rust profile.
Credential operations preserve the C raw 1..=8-byte form explicitly, without
relaxing default Rust credential construction. Reader names retain stable slot IDs within
one initialized lifetime; removal includes the last reader.

## Hardware versus host crypto

The card performs private-key operations, key generation/import, PIV object writes
and supported token RNG. The host performs hash/padding/KDF, RSA/ECDSA/ML-DSA verify,
RSA public encryption, ML-KEM encapsulation and session AES/generic-secret creation.
Mixed mechanisms do not advertise CKF_HW for their host operations. SM2 uses explicit
vendor RAW/SM3 signing and DERIVE mechanisms; it never aliases ECDSA/ECDH or claims
host Verify. The card performs its SM3/identity hashing and agreement KDF. Agreement
publishes a session secret with its public ephemeral point under the same reservation.

Physical key move/delete uses one vendor function with an FF deletion target;
certificates are independent. Attestation returns DER without a trust decision.
Management-key rotation can maintain PIN-managed PRINTED, with explicit partial-write
recovery; retry-limit setting resets credentials and refuses PIN-managed policy.
Both credential mutations revoke host credentials/private contexts on attempted I/O.

## Build and diagnostics

Cargo.toml pins libcanokey; Cargo.lock pins its dependency closure. The private Rust
static library is linked into the existing DLL, with no Rust DLL or submodule.
ThinLTO and function/data section collection remove unused code. PIV-only C ABI
features exclude unrelated applets; host crypto, curves and Rust runtime still
contribute to size. Removing unreachable source need not shrink linked code.
ELF links hide Rust archive symbols from the public ABI. Standard Rust Windows
MSVC targets do not establish Windows 7/8.1 runtime compatibility.

CNK_EXTERNAL_CALL/CNK_EXTERNAL_VOID record each completed Rust/PCSC boundary at
DEBUG, including Release: function name and status only. The owned CnkError POD
additionally preserves kind, phase, reference and optional SW/retries before the
operation is freed. C maps it to CK_RV; the minidriver maps CK_RV to Windows status.
No TLS/global last-error object is used. Raw APDUs require explicit sensitive-data
logging. Managed logging borrows the caller's FILE and must be rebound before
reinitializing after finalization. Detailed C function entry/return traces remain
subject to CNK_VERBOSE.

Run the gates in [validation.md](validation.md) and the migration plan. Hardware
scripts use explicit card/slot selections and generated reports. Legacy broad real
executables can overwrite provisioned slots when destructive flags are enabled;
they do not replace independent crypto verification or Windows propagation checks.

Agreement and KEM session-secret templates share one C prototype builder. It owns
PKCS#11 defaults, attributes, visibility and length checks; card-side SM2 KDF and
host-side ECDH KDF feed the same allocator. A shared private-operation admission
counter allows queued sign/decrypt calls while excluding concurrent key/credential
mutations. Exclusive token reservations remain responsible for one-shot result commit.
