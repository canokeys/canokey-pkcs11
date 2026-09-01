# CanoKey PKCS#11 Architecture

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
extensions, and token randomness. `backend/pcsc.c` still combines reader/
transaction transport with PIV auth, data, and private-key commands; future
splits should preserve managed mode, where the minidriver supplies an existing
card handle and every operation must balance `SCardBeginTransaction` with
`cnk_disconnect_card`.

## State Ownership

Authentication is token-scoped, not session-scoped. One
`CNK_PKCS11_TOKEN_STATE` per slot owns the USER PIN cache, management-key cache,
login role, and session counters. Its lock protects all of those fields.

Each `CNK_PKCS11_SESSION` owns active operation contexts, copied mechanism
parameters, bounded multipart buffers, session-only secret keys, and find
state. It references, but does not own, token authentication state.

Closed sessions are retired until `C_Finalize`. This keeps pointers returned by
session lookup stable if another thread closes the handle. Finalize frees
retired sessions and zeroizes every sensitive cache and session key.

Combined-hash Sign and Verify borrow the session digest context. Their
operation contexts record that ownership so cancellation clears only the
digest they created. Raw Sign/Verify can coexist with an independent Digest.

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

## Firmware Gates

- PIV 5.7+ provides the metadata directory and runtime PQ algorithm IDs.
- PIV 6.0+ provides unauthenticated token randomness through `00 84`.

Older firmware uses per-slot probes, does not advertise PQ mechanisms, and
does not set `CKF_RNG`.

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
on current hardware.

## Remaining Structural Work

The current large files still have identifiable future boundaries:

- `backend/pcsc.c`: separate reader/transaction transport, PIV authentication,
  PIV data objects, and private-key commands.
- `api/object.c`: separate enumeration/handle validation from class-specific
  attribute readers. Wire encoding has already moved out.
- `api/sign.c`: separate Verify after extracting one shared signature-mechanism
  descriptor layer; splitting first would duplicate RSA/ECDSA mechanism rules.
- `api/slot.c` and signature/encryption dispatch: converge mechanism lists,
  flags, key sizes, and dispatch validation on one descriptor table.

These are ownership-driven splits. File length alone is not a reason to create
another module or expose a formerly static helper.
