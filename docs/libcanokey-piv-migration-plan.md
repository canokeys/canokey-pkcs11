# libcanokey PIV migration

The production PIV protocol cutover and current-card x64 acceptance are complete.
Native ARM64 runtime acceptance is excluded from the current task; ARM64 and
Arm64X cross-builds remain checked. Companion PRs retain exact dependency pins.

## Ownership after migration

| PKCS#11 / minidriver | libcanokey |
| --- | --- |
| PC/SC reader, connection and transaction lifetime | SELECT, VERIFY, management authentication and APDU conversations |
| Sessions, token authorization, credentials and reservations | Firmware/profile rules and semantic algorithm-to-wire resolution |
| PKCS#11 mechanisms, host hashing, RSA padding and KDF | Card sign/decrypt/agreement/decapsulation formats |
| Windows provider mapping, key blobs and byte order | PIV metadata, directories, names, objects and certificates |
| Public caches, output ownership, CK_RV and commit classification | Key/data/certificate mutations, bounded parsing and typed errors |

All production transmission uses one C executor and raw PC/SC exchange. Rust
owns chaining, continuation and protocol parsing. The C APDU builders/decoder,
credential/data/public-key TLV parsers, certificate framing, management 3DES,
legacy callback adapter and per-session wire algorithm maps have been removed.
C retains PKCS#11 admission, host crypto, caches and Windows representations.

## Acceptance by area

| Area | Deterministic acceptance | Current-card acceptance |
| --- | --- | --- |
| Profile/context | Selected-context factories, profile expiry/binding races, cache generations, lock failures, concurrent sign/RNG, close/finalize drain | Two sessions, external replacement and USB reinsert against a live cached session |
| Public reads | Metadata, directory, definite BER, malformed/duplicate fields, certificate decompression/limits, buffer atomicity and cache invalidation | Fresh enumeration, PRINTED roundtrip, six Windows certificate files and propagation |
| Signing | RSA/ECDSA/Ed25519/ML-DSA formats, policy/init/cancel/short-buffer boundaries, legacy/unknown feature gates | Independent verification and all three PIN policies across supported variants |
| Other private operations | RSA preflight retains authorization without APDUs; ECDH/ML-KEM reservations cover session-secret publication/failure | RSA raw/PKCS#1/OAEP, ECDH/X25519 and ML-KEM; Windows RSA decrypt and P-256/P-384/P-521 raw-secret byte order |
| Management/writes | Management transcripts, typed inputs, failed writes, protection parsing and one-transaction PUK recovery | Key generation/import, certificate/data/name writes, PIN/PUK change/reset/restore and configured PIN-managed login/finalization |
| Windows integration | API ownership contracts, enrollment rollback and cache/name boundaries | Six certificates propagated with stable associations; CAPI/CNG crypto and 18 DDI generation/import cases |

The C regression entry points are `test/contract/piv-operation.c`,
`piv-management.c`, `piv-recovery.c`, `piv-transactions.c`, `key-write.c` and
`container-name.c`. Libcanokey's PIV transcript/parser and C/C++ ABI suites verify
the protocol side. [validation.md](validation.md) defines failure-injection,
sanitizer and review requirements; [api-contracts.md](api-contracts.md) contains
the complete exported inventory and lifetime/exit guarantees.

## Boundaries that must remain true

- A card call owns one transaction from begin through SELECT, authentication,
  dependent commands and result/cache commit. CanoKey SELECT resets authentication;
  selected-context factories neither SELECT nor probe.
- Resolve the immutable profile before authentication. Clone it under the token
  lock and reject an obsolete binding epoch. Refresh failure cannot authorize
  fallback. Finalize/binding changes stop admission and drain active calls.
- Reservations retain authorization through card I/O and result publication.
  Logout excludes newly admitted private/mutation work. Failed commits return no
  provisional handle. Dropping a Rust operation is not card rollback.
- Size queries and short output buffers do not consume private operations or
  transmit APDUs. RSA decrypt uses the conservative mechanism bound permitted by
  PKCS#11 3.2 section 5.2; callers retry with that capacity.
- PIN-always sign/decrypt permit one operation-local context login. One-shot
  derive/decapsulation remain fail-closed. PUBLIC PIN changes authenticate the
  supplied old PIN and retain PUBLIC state without caching a new credential.
- PUK recovery reads public policy without submitting a cached PIN, then checks
  protection and performs the mutation in the same selected transaction.
  PIN protection forbids recovery even if the PUK-blocked claim is missing/false.
- Mutations never replay automatically. Uncertain writes invalidate affected
  public caches before transaction release. Cache generations reject late reads;
  managed mode bypasses the public cache.
- Every external Rust/PCSC and minidriver-to-PKCS#11 call emits DEBUG completion,
  including successes and frees in Release. Structured errors retain kind, phase,
  reference, status word and retry presence. Secret arguments are not logged;
  raw APDU logging requires its separate opt-in.

Development firmware uses its declared base version while retaining its original
identity. Unsupported and unknown remain distinct. F5 errors on supported
firmware never select legacy fallback. CKO_DATA retains container framing;
certificate consumers receive final DER. P-521 definite-BER responses and digest
normalization are handled once by the protocol owner.

## Reproducible hardware checks

The development reader is `canokeys.org OpenPGP PIV OATH 0`, serial `0`, firmware
`3.1.0-dev+gaa408988`, PIV `6.0.0`. Always re-enumerate before provisioning.

- `scripts/hardware-crypto-test.py`: Debug and Release each pass 55 selected
  groups, including all supported key variants, PIN policies, independent
  OpenSSL verification, concurrent operations, certificate deletion preserving
  keys, RNG beyond 64 KiB, external replacement/reset and credential restoration.
- `scripts/hardware-pin-managed-test.py`: explicit development fixture for
  PIN-managed finalization/login, blocked recovery and restoration. Check the
  authenticated retry-reset path first; always restore in the caller's `finally`.
  Its separate `clear-slot` mode deletes only an explicitly selected test key.
- The minidriver's `keygen-test.ps1` passes generation and import for RSA
  signature/key-exchange at 2048/3072/4096 bits and ECDSA P-256/P-384/P-521.
  Imported public keys match the software source. Original valid keys in 9A,
  9C and 82 are retained; 9D/9E/83 are explicit replaceable Windows fixtures.
- `--self-signed-certificate-id` writes a certificate signed by the existing
  card key and backs up previous DER. It needs `asn1crypto` only for this mode.
  The minidriver propagation test observes removal and recreation of all six
  selected user-store certificates, verifies provider/container/KeySpec stability,
  then verifies signatures against each certificate's public key.
- Native x64 DDI tests cover six certificate reads/writes, PUBLIC rejection,
  ADMIN writes, USER signatures and P-256/P-384/P-521 raw ECDH. CAPI SHA1/SHA256,
  CNG RSA PKCS#1/PSS/ECDSA and RSA PKCS#1/OAEP decrypt pass. Targeted silent
  `certutil -scinfo` succeeds; development certificate trust is a separate issue.

Temporary protection is removed after testing. The development PIN/PUK, retry
limits and default management key are restored. Reports retain selections, DLL
hashes, certificate backups and results; generated keys/logging chronology stay
out of the repository. Older physical firmware and native ARM64 interoperability
are not inferred from these current-card results.
