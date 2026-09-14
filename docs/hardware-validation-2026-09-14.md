# Real hardware validation — 2026-09-14

Both the Windows x64 Debug and Release DLLs passed **14/14 explicitly selected
hardware check groups**, using the repaired PKCS#11 adapter and libcanokey
`f961dc2`. These are actual card operations with software verification, not
replayed APDU fixtures. Earlier offline results did not establish this coverage.

## Device and reproducible evidence

- Reader: `canokeys.org OpenPGP PIV OATH 0`.
- PKCS#11 slot: `0`; token serial: `0`.
- Actual Admin firmware: `3.1.0-dev+gaa408988`; PIV application: `6.0.0`.
- The management key was restored to the documented default at the user's
  request. Fresh authentication and later PKCS#11 certificate writes verified it.
  The previously supplied key is not stored in source or this report.
- The test requires Python with `cryptography`. RSA/ECDSA/Ed25519 signatures and
  EC/X25519 agreements are verified with independent software implementations.
  ML-DSA uses the PKCS#11 host verifier; ML-KEM compares host encapsulation with
  the card's decapsulation. No private values or shared secrets are printed.

| DLL | SHA-256 |
| --- | --- |
| x64 Debug | `ce4deeb0ccd07887f8f11e94a33b6ab9cdb4bb0bafae2c0a2dcd191d1f10ccb7` |
| x64 Release | `7944f91818cb543abf16133a5798a26829eb5a8d4ec9db59e0cc9a6f6f29ed3b` |

Machine-readable reports, including timestamp and DLL hash, are under
`build-windows-x64-Debug/hardware-results-debug.json` and
`build-windows-x64-Release/hardware-results-release.json`. Build outputs and
raw diagnostic logs are intentionally not tracked.

## Verified operations

| Operation | Card objects (hex IDs) | Result |
| --- | --- | --- |
| ECDSA P-256 with SHA-256/SHA-512 digests | 01/9A, 02/9C | Verified by software |
| ECDSA P-384 with both digests | 05/82 | Verified by software |
| ECDSA P-521 with both digests | 0B/88 | Verified by software after BER/digest fixes |
| Ed25519 | 0D/8A | Verified by software |
| ECDH P-256/P-384/P-521 | 01/9A, 02/9C, 05/82, 0B/88 | Exact software-secret comparison |
| X25519 | 0C/89 | Exact software-secret comparison |
| RSA-2048 SHA-256 PKCS#1 v1.5 and PSS | 0A/87 | Verified by software |
| RSA-2048 PKCS#1 v1.5 and OAEP-SHA256 decrypt | 0A/87 | Exact plaintext comparison |
| ML-DSA-65 | 17/94 | Hardware sign and host verify |
| ML-KEM-768 | 18/95 | Matching encapsulated/decapsulated secrets |
| Certificate write/read/delete | 0A/87 | Exact DER bytes, deletion confirmed, key retained |
| Token RNG | 1024 bytes | Multiple APDUs; basic nondegeneracy check |

Signing checks include size-query and short-buffer retry semantics. RNG output
checks do not establish statistical quality or entropy certification.

RSA-2048, P-521, X25519 and Ed25519 keys were generated on the card in previously
empty slots **87, 88, 89 and 8A**, respectively. The first three were subsequently
imported from newly generated software private keys, with exact public-key
comparison and successful operation retests. These four test keys remain for
repeatable validation. Temporary certificates on 87 were deleted.

## Problems found and repaired

1. Development firmware was rejected before metadata I/O. As requested,
   compatibility now uses the declared numeric base version while retaining the
   original suffix and keeping unknown base versions conservative.
2. The new private-operation factories rejected ECDH on 9A/9C. They now accept
   all evidenced ordinary asymmetric slots; consumer usage policy and card PIN
   authorization still apply.
3. Raw PIV-object consumers lost the outer container, and writes could add it
   twice. Explicit container factories preserve the compatibility boundary;
   normalized certificate payloads no longer pass through the retired C parser.
4. P-521 GA replies use definite BER lengths such as `82 00 8F`. The envelope
   parser now accepts these forms while preserving bounds and strict DER
   signature parsing. C also preserves short digest lengths so normalization
   and the P-521 bit shift occur exactly once.

The raw-container change has deterministic C/Rust coverage. The actual card's
ADMIN DATA is empty, so it does not provide a positive PIN-managed-login fixture.

## Pre-existing card anomalies and coverage limits

These findings were recorded before provisioning the new test fixtures:

- **9D and 9E:** metadata reports RSA-3072 but the returned modulus is even,
  with trailing zero data. Direct OpenSC raw metadata reads reproduce this;
  the positive RSA matrix therefore uses the new 87 key.
- **85:** the existing X25519 public key and private operation do not produce
  the same secret as software. The new generated and imported X25519 fixture
  on 89 passes using the same implementation.
- **86:** the directory advertises a key, but GET METADATA returns `6900`.

Those original slots were not reprovisioned. The legacy `test_real.exe` run is
not reported as passing: it selects invalid existing RSA material, includes a
read-only SO-login probe, and several errors only appear as printed messages.
The new script uses explicit key selections and exits nonzero for failed checks.

This run does not establish native ARM64 runtime behavior, Windows certificate
propagation, reset/reinsert recovery, complete concurrent-session behavior, or
the complete PIN-never/PIN-always policy matrix. These remain migration gates.

## Repeat the focused matrix

Set `CNK_PIV_PIN` and `CNK_PIV_MANAGEMENT_KEY` in the process environment. The
management value is required only when requesting the certificate mutation test.
The script verifies the selected token serial, disables sensitive APDU logging,
and refuses to overwrite an existing certificate. It never generates or
replaces private keys.

```powershell
python scripts/hardware-crypto-test.py `
  --module build-windows-x64-Debug/canokey-pkcs11.dll --slot 0 --serial 0 `
  --ecdsa-id 01 --ecdsa-id 02 --ecdsa-id 05 --ecdsa-id 0b --eddsa-id 0d `
  --derive-id 01 --derive-id 02 --derive-id 05 --derive-id 0b --derive-id 0c `
  --rsa-id 0a --mldsa-id 17 --mlkem-id 18 --certificate-id 0a `
  --report build-windows-x64-Debug/hardware-results-debug.json
```

Use the corresponding Release paths to repeat that build's matrix. Omitting
`--certificate-id` omits certificate writes/deletion. Use other explicit key IDs
only after enumerating their actual types and policies.

## Typed import and certificate regression

After removing C import/certificate framing, the x64 Debug and Release matrices
again pass 14/14 groups (build-windows-x64-Debug/c-reduction-hardware.json and
build-windows-x64-Release/c-reduction-hardware.json). The explicit
--replace-import-rsa-id 0a, --replace-import-p521-id 0b,
--replace-import-x25519-id 0c and --replace-import-ed25519-id 0d run replaces only
the four test keys created during this session. Every imported public key matches
the software-generated key exactly; RSA sign/decrypt, P-521 sign/derive, X25519
agreement and Ed25519 signatures pass independent verification. The import report
is build-windows-x64-Release/c-reduction-imports.json. Both scripts verify slot 0
and serial 0 before opening a write session. Originals remain unchanged.

The corresponding minidriver propagation test now also reaches native x64
CertPropSvc and Windows KSP. The matching 9A/9C/82 certificates are removed from
the user store only after serializing their contexts, then automatically reappear
after USB reinsertion with identical provider/container/KeySpec properties.
KSP signatures verify against the certificates themselves. Existing invalid RSA
material on 9D/9E prevents claiming a complete Windows matrix; the original binary
shows the same problem. See the minidriver propagation report for fingerprints,
artifact hashes, service log evidence and rollback verification.
