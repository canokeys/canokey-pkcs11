# libcanokey PIV migration

This is the shared acceptance plan for PKCS#11 and the sibling libcanokey PR.
Migration is incomplete. Delete a C protocol path only after its Rust replacement
passes the corresponding contract and hardware gates; do not add silent fallback.

## Ownership

| PKCS#11 / minidriver | libcanokey |
| --- | --- |
| PC/SC reader, connection and transaction lifetime | SELECT, VERIFY, authentication and APDU conversations |
| Session/token/object state, credentials and reservations | PIV metadata, directory, object and certificate formats |
| Mechanisms, hashing, RSA padding and KDF | Card signing/decrypt/agreement/decapsulation formats |
| Windows provider mapping and byte order | Key/certificate/data mutations and firmware capability rules |
| Public caches, output buffers, CK_RV and rollback classification | Bounded parsing, typed card errors and zeroizing temporary copies |

## Current implementation and remaining work

| Stage | Implemented | Required before completion |
| --- | --- | --- |
| 0: profile/context | Immutable token profile with binding epoch; copied selected contexts; bounded executor and two-session transaction contract | Full reset/invalidation, close/finalize and concurrent transaction matrix |
| 1: public reads | Typed metadata/public keys, certificates, session data, directory and ordinary/F9 name reads | Complete malformed/duplicate/gzip/buffer/cache matrix |
| 2: signing | RSA, ECDSA, Ed25519 and streaming ML-DSA use Rust operations | Complete PIN-never/once/always, legacy-Le, size-query and cancellation matrix |
| 3: other private operations | RSA decrypt, ECDH/X25519 and ML-KEM use Rust operations | Full PIN-policy, Windows endian/KDF and concurrent result-publication matrix |
| 4: management/writes | Management challenge-response, key generation/import, certificate/data/F5 writes and certificate deletion | Credential commands and management metadata are migrated; complete write/failure matrix |
| 5: remove duplicate C | Removed C APDU builders, credential/data/public-key parsers, 3DES the legacy callback adapter and session algorithm maps | Complete acceptance matrix |

All production card transmission now flows through one C executor and raw PC/SC
exchange. Rust owns SELECT, credential commands, metadata, version/configuration,
RNG and empty-slot semantics; the old C APDU decoder/Rust callback adapter is gone.
Credential byte compatibility is explicit, and temporary PIN tests restore the
original value. C still owns cache updates, reservations and provisioning policy.

C now passes semantic import parameters and component views directly to Rust.
C retains PKCS#11 RSA-width admission and one bounded, zeroized EC-padding buffer.
No C import/public-key TLV encode/reparse or certificate framing remains. C uses semantic algorithm codes throughout; the immutable Rust profile owns
support checks and wire-ID resolution. Logical sessions keep no algorithm maps. ADMIN DATA/PRINTED use Rust parsing, with empty policy distinguished
from malformed data and PIN protection forbidding PUK recovery independently of
the stored PUK-blocked claim. Public recovery reads never submit a cached PIN. Host crypto and
PKCS#11 state are intentional C responsibilities, not migration leftovers.

## Required invariants

- A card call owns one transaction: connect -> begin -> SELECT -> optional
  VERIFY/management authentication -> dependent command -> parse/commit -> end.
  CanoKey SELECT resets authentication; a selected-context factory must not SELECT.
- Probe before authentication. Publish a profile only after rechecking binding
  generation; clone it under the token lock. Rust operations never borrow a profile
  across unlock, close, finalize or invalidation.
- Finalize/binding changes stop admission, drain active calls, invalidate/free
  profiles, then release PC/SC ownership. Session locks must not invert table locks.
- A token reservation is the card-operation admission point. Logout revokes work
  not admitted; admitted work retains authorization through I/O and result commit.
- NULL/short output preflight must not consume a private operation or send APDUs.
  Getters never advance. Malformed/partial results must not be published.
- PIN-always sign/decrypt permit one operation-local context login. One-shot
  derive/decapsulation fail closed; no implicit PIN replay or retry.
- Mutations never replay automatically. Dropping an operation is not rollback.
  An uncertain write invalidates affected public caches before transaction release.
- Public cache entries contain no credentials, handles or selected/authenticated
  state. Managed mode bypasses the PKCS#11 cache; every read checks freshness.
- Every external Rust/PCSC call emits a DEBUG completion record, including success
  and frees, in Release too. Records contain names/statuses, not secret arguments.
  Structured failures retain kind, phase, reference, SW and retry presence.

The exact per-entry lifetime/exit contracts remain in [api-contracts.md](api-contracts.md).
Firmware support distinguishes unknown from unsupported. Development firmware uses
its declared base version while retaining the original identity; unknown future
base versions remain unknown. F5 failures on supported firmware must not trigger
legacy fallback. Raw CKO_DATA consumers retain container framing; certificate
consumers receive the unwrapped/decompressed payload. P-521 accepts definite BER
response envelopes and normalizes digests exactly once.

## Required verification

Each changed protocol path must cover a successful transcript, malformed/truncated
and duplicate fields, missing objects, short buffers, rejected credentials, limits,
and failure at every external call. Check resource counts, output atomicity,
reservation cleanup and cache invalidation together. Multi-APDU tests must prove
one SELECT and one uninterrupted transaction, including concurrent sessions.

Run libcanokey workspace tests/doctests, strict Clippy, rustdoc and C/C++ ABI tests;
PKCS#11 API inventory, unit/contract tests, Linux CTest, ASan/UBSan/leak checks;
Windows x86/x64/ARM64 Debug/Release builds and native tests; and diff/format checks.
Keep companion dependency pins exact. Reply to each actionable PR review finding.

Hardware acceptance includes fresh enumeration and certificate propagation; all
supported signature, RSA decrypt and agreement algorithms; certificate/data/name
writes; key generation/import; PIN policies; reset/reinsert; and minidriver reads
and writes through Windows. Use explicit reader/serial/slot selections and preserve
original material. Native ARM64 acceptance requires native hardware, not x64
emulation. Passing a selected subset does not close the remaining gates.

## Current hardware evidence

Reader: canokeys.org OpenPGP PIV OATH 0; serial 0; firmware
3.1.0-dev+gaa408988; PIV 6.0.0. Re-enumerate before any provisioning.

- x64 Debug/Release: 30 selected groups pass using scripts/hardware-crypto-test.py:
  PIN change/cache/fresh-login/restore, F5 read/write/clear/restore, unconfigured
  protection rollback, six key generations, six imports, independent private-operation
  verification, host RSA encryption and RSA/ECDSA verification, concurrent ECDSA/RNG
  from two sessions, certificate write/read/delete and RNG across the 64 KiB boundary.
- Test slots 87..8A: RSA (2048/3072/4096), P-521, X25519 and Ed25519 generation/import
  match public-key expectations and pass private operations. Slot 87 currently
  holds the most recently tested RSA size; temporary certificates also use it.
- Unconfigured PIN-managed login returns its expected policy error and rolls back
  USER state on the actual card. Malformed/protected PUK recovery uses a counted
  mutation seam with the real Rust parser; real PUK mutation remains unverified.
- Native x64 minidriver: two DDI lifetimes pass certificate read/write, PUBLIC
  write rejection, ADMIN authorization and USER signatures on 9A/9C/82.
  Earlier propagation passed for these certificates, with signatures verified
  against their public keys; the latest DLL needs an unlocked-session rerun.
  Reset failure restores certificate contexts; locked-session preflight prevents
  certificate removal. Original and new DLLs both failed to propagate while locked.
- Current original 9D/9E RSA metadata/certificate associations, 85 X25519 material
  and 86 metadata have independent anomalies. Slot 83 is SM2 and outside the
  Windows view. These prevent claiming complete card/Windows acceptance.
- Native ARM64 runtime and the complete PIN/reset/concurrency/write matrix remain
  unverified. The minidriver must rebind logging before each C_Initialize.

The test scripts write machine-readable reports with explicit selections and DLL
hashes. Generated logs, key material and debugging chronology stay out of docs.
Current build/link/logging constraints are in [architecture.md](architecture.md);
F5 compatibility requirements are in [container-names.md](container-names.md).
