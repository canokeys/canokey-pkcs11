# Agent Notes

## Build Environment

- Use the Windows native Visual Studio 2022 x64 environment.
- The VS CMake executable is:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe`
- The VS bundled Ninja executable is:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe`
- The working x64 ClangCL compiler is:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-cl.exe`
- The Visual Studio generator with `-T ClangCL` currently fails with `MSB8020` because the ClangCL platform toolset is not registered in this VS installation. Use Ninja and pass both C and C++ compilers explicitly.

Recommended configure command from the repository root:

```bat
cmd.exe /s /c "\"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat\" -arch=x64 -host_arch=x64 && \"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe\" -S . -B build-ninja-clangcl-x64 -G Ninja -DCMAKE_MAKE_PROGRAM=\"C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/Ninja/ninja.exe\" -DCMAKE_C_COMPILER=\"C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin/clang-cl.exe\" -DCMAKE_CXX_COMPILER=\"C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/Llvm/x64/bin/clang-cl.exe\" -DCMAKE_BUILD_TYPE=Debug"
```

Recommended build command:

```bat
cmd.exe /s /c "\"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat\" -arch=x64 -host_arch=x64 && \"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe\" --build build-ninja-clangcl-x64 -v"
```

The DLL output is:

```text
build-ninja-clangcl-x64\canokey-pkcs11.dll
```

The crypto backend is bundled TF-PSA-Crypto from:

```text
external\tf-psa-crypto\
```

Some TF-PSA-Crypto development checkouts do not include generated source
files. The top-level CMake enables `GEN_FILES` automatically when those files
are missing. Install the generator dependencies before building such a checkout:

```powershell
python -m pip install -r cmake\tf-psa-crypto-generator-requirements.txt
```

CI uses `actions/setup-python` and passes that exact interpreter to CMake as
`Python3_EXECUTABLE`, so TF-PSA-Crypto's generators run with the same Python
environment that received the `pip install`. CI currently uses Python 3.14;
the generator requirements are verified on Ubuntu, Windows, and macOS. The
local requirements file is kept narrower than TF-PSA-Crypto's upstream
`basic.requirements.txt` to avoid unneeded typing-stub packages and old
MarkupSafe constraints during CI builds.

Bundled static dependencies are built with position-independent code because
the PKCS#11 module and unit-test shim are shared libraries on Unix-like hosts.

`external\mbedtls\` was removed from the tracked submodules after the
TF-PSA-Crypto migration.

## Development Hygiene

- English is the project language. Write source comments, documentation,
  diagnostic text, commit messages, and pull-request content in English.
  Other languages are allowed only in explicitly identified localization
  resources.
- Before committing C source or header changes, run `clang-format` on the
  touched `.c` and `.h` files only. Do not run `clang-format` on CMake files.
- Add succinct comments for non-obvious invariants and boundaries: sensitive
  data ownership/zeroization, operation-state lifetime, two-stage output
  retries, wire encodings, endianness, and host-versus-card responsibilities.
  Do not add comments that merely restate the next line of code.
- Keep session lock ordering explicit: `session_mutex` protects the table and
  active-call references, but close must release it before acquiring a
  per-session lock. Scoped cleanup must release the session lock before the
  session reference.
- Every API path that calls `cnk_session_find()` must declare its pointer with
  `CNK_SESSION_REF`; otherwise concurrent close can either leak or free the
  session too early.
- Cryptographic operation contexts are protected by `session->lock` for the
  complete API call. `C_SessionCancel` and close use the same lock before
  freeing copied parameters, buffered messages, or hash contexts.
- Update `docs/architecture.md` when moving ownership, adding an internal
  layer, or changing the host/card responsibility boundary.
- The VS bundled formatter is:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-format.exe`
- Commit messages must follow Conventional Commits, include enough detail in the
  body for non-trivial changes, wrap subject/body lines to 80 columns, and use
  signoff (`git commit -s`).

## OpenSC Test Tool

Use this installed pkcs11-tool:

```text
C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe
```

Basic standalone smoke test:

```powershell
& 'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe' --module "$PWD\build-ninja-clangcl-x64\canokey-pkcs11.dll" --show-info
```

Useful follow-up probes:

```powershell
& 'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe' --module "$PWD\build-ninja-clangcl-x64\canokey-pkcs11.dll" --list-slots
& 'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe' --module "$PWD\build-ninja-clangcl-x64\canokey-pkcs11.dll" --list-mechanisms --slot-index 0
& 'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe' --module "$PWD\build-ninja-clangcl-x64\canokey-pkcs11.dll" --list-objects --slot-index 0
```

## Historical CanoKey Probe Notes

These observations came from an earlier, mostly empty development-card state.
They are useful compatibility history, not the current object inventory.
`opensc-tool --list-readers` reported:

```text
0    Yes             canokeys.org OpenPGP PIV OATH 0
1    Yes             Windows Hello for Business 1
```

The standalone CanoKey module sees slot 0 as:

```text
Slot 0 (0x0): CanoKey Dev
token label: CanoKey PIV #4294967295
firmware version: 3.3
serial num: 4294967295
```

OpenSC's own `opensc-pkcs11.dll` sees the same PIV token differently:

```text
token label: PIV_II
serial num: 1286a07b8d6ef74f
```

`piv-tool --reader 0 --name` identifies `Personal Identity Verification Card`.
`piv-tool --reader 0 --serial` returns a 16-byte value ending in `1286a07b8d6ef74f`, while this module reads the CanoKey private hardware serial as `FFFFFFFF`. That `FFFFFFFF` value is expected for the current development hardware and should not be treated as a bug by itself.

Observed APDU behavior for the inserted key:

- PIV select succeeds with AID `A000000308`.
- Certificate GET DATA probes for the current mapped PIV slots return `6A82`.
- Key metadata probes for `9A/9C/9D/9E/82/83` return `6A88`.
- After local fixes, `pkcs11-tool --list-objects --slot-index 0` completes successfully and returns no objects instead of aborting.

Local compatibility fixes made during probing:

- Empty `C_FindObjectsInit` templates now enumerate certificate, public-key, and private-key classes instead of ending the find operation immediately.
- `MAX_FIND_OBJECTS` must fit 6 PIV slots x 3 key/certificate classes, fixed
  PIV data-object candidates, and session-only secret keys.
- `cnk_get_metadata()` maps `6A82` and `6A88` to `CKR_DATA_INVALID` so object enumeration skips missing PIV keys.

## Current Dev Hardware PIV State

The inserted development key uses the default CanoKey PIV credentials:

```text
PIN: 123456
PUK: 12345678
Management Key: 010203040506070801020304050607080102030405060708
```

`piv-tool` expects the management key as colon-separated bytes through `PIV_EXT_AUTH_KEY`.

Prepared objects on the current key:

```text
ID 01 -> slot 9A -> EC P-256 key
ID 02 -> slot 9C -> EC P-256 key
ID 03 -> slot 9D -> EC P-256 key
ID 04 -> slot 9E -> RSA-2048 key
ID 05 -> slot 82 -> EC P-256 key
ID 06 -> slot 83 -> EC P-384 key
ID 07 -> slot 84 -> EC P-521 key
ID 08 -> slot 85 -> Ed25519 key
ID 09 -> slot 86 -> X25519 key
ID 23 -> slot 94 -> ML-DSA-65 key
ID 24 -> slot 95 -> ML-KEM-768 key
```

Certificates are independent PIV data objects and may not exist for every key
listed above. Re-enumerate metadata before relying on this table because
destructive tests intentionally overwrite selected slots.

The current firmware reports platform revision `gcdc54046`, canokey-core
revision `3d602057`, and PIV application version `6.0.0`.

OpenSC's own module is useful as an external comparison point:

```text
C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll
```

Write-path notes:

- `C_GenerateKeyPair`, `C_CreateObject(CKO_PRIVATE_KEY)`, and
  `C_CreateObject(CKO_CERTIFICATE)` require a read-write session logged in as
  `CKU_SO` with the PIV management key.
- These operations overwrite the selected PIV slot/object. Avoid using ID 03
  / slot 9D for destructive development probes because it is also used by
  another project.
- Private-key import currently accepts explicit PKCS#11 template components:
  RSA CRT attributes (`CKA_PRIME_1`, `CKA_PRIME_2`, `CKA_EXPONENT_1`,
  `CKA_EXPONENT_2`, `CKA_COEFFICIENT`) or an EC private scalar in
  `CKA_VALUE` with matching `CKA_EC_PARAMS`.
- PKCS#11 3.2 PQC import accepts seed-based private-key templates. ML-DSA-65
  uses a 32-byte `CKA_SEED`; ML-KEM-768 uses a 64-byte `CKA_SEED` (`d || z`).
  Both require the matching `CKA_PARAMETER_SET`. Expanded-only `CKA_VALUE`
  import is unsupported because CanoKey persists the compact seed.
- PIV token-object deletion is not implemented. Session secret keys are
  securely destroyable, but there is no standard PIV APDU that deletes both a
  certificate and private key with PKCS#11-style object semantics.
- Windows minidriver `CardQueryFreeSpace` should report unknown free space for
  now. There is no PIV APDU for real object-store capacity, and adding one would
  require extending the CanoKey PIV applet.
- PKCS#11 login state is token-scoped, not session-scoped. PIN and management
  key caches live in `CNK_PKCS11_TOKEN_STATE`; all sessions derive their state
  from that object. Last-session close and finalize must zero those caches.
- PIV PIN-always maps to `CKA_ALWAYS_AUTHENTICATE` and requires
  `C_Login(CKU_CONTEXT_SPECIFIC)` after operation init. The context PIN is
  operation-local, must not enter the token USER cache, and is consumed and
  zeroized after one operation or cancellation.
- Every PKCS#11 3.2 function-list entry must be non-NULL. Unsupported 3.x APIs
  use type-correct stubs returning `CKR_FUNCTION_NOT_SUPPORTED`. RSA/ECDSA/
  ML-DSA Verify and RSA public-key Encrypt are host-side implementations; do
  not mark mixed host/card mechanism capabilities with `CKF_HW`.
- P-521 is a standard `CKK_EC` curve and is supported for generation, import,
  ECDSA sign/verify, and ECDH. Ed25519 and X25519 use
  `CKK_EC_EDWARDS`/`CKK_EC_MONTGOMERY` with RFC 8410 OIDs. Ed25519 currently
  advertises pure `CKM_EDDSA` signing only; do not claim host verification
  until the bundled crypto provider supplies a compatible primitive. PKCS#11
  3.2 has no SM2 mechanism, so expose the SM2 object identity without mapping
  it to `CKM_ECDSA`.
- Host Verify supports RSA PKCS#1 v1.5/PSS, ECDSA, and ML-DSA-65 in single-part
  and streaming forms. Host Encrypt supports single-part RSA X.509, PKCS#1
  v1.5, and OAEP. OAEP mechanism copies must deep-copy `pSourceData` so caller
  label lifetime does not leak into an active operation.
- Standalone `C_WaitForSlotEvent` uses PC/SC status-change notifications and
  the PnP pseudo-reader. `CKF_DONT_BLOCK` returns `CKR_NO_EVENT` when nothing
  changed, and `C_Finalize` cancels a blocking wait. Managed mode returns
  `CKR_FUNCTION_NOT_SUPPORTED` because the host owns its PC/SC lifecycle.
- `C_CNK_SetPIN()` maps to the standard PIV Change Reference Data APDU. Pass
  `CNK_PIV_PIN_TYPE_PIN` (`0x80`) to change the PIN or
  `CNK_PIV_PIN_TYPE_PUK` (`0x81`) to change the PUK; the optional tries output
  reports remaining retries for the selected secret when the card returns a
  retry status. Standard `C_SetPIN` forwards to the PIN form without a tries
  output. PUK unblock is exposed as the CanoKey extension `C_CNK_UnblockPIN()`
  and maps to Reset Retry Counter (`00 2C 00 80 10 puk new-pin`). CanoKey
  core's PIV applet implements these APDUs with the same fixed 8-byte,
  `0xFF`-padded fields.
- `C_CNK_LoginPinManaged()` checks Yubico-compatible ADMIN DATA (`5FFF00`)
  for both PUK-blocked and PIN-protected bits, confirms the actual PUK retry
  counter is zero, reads the protected management key from PRINTED (`5FC109`),
  verifies it, and clears all temporary data before returning.
  Keep ADMIN DATA and PRINTED parsing inside this extension so managed callers
  never receive the raw management key.
- `C_CNK_FinalizePinManaged()` is an explicitly destructive provisioning
  operation. It authenticates USER and the protected management key before
  permanently blocking the PUK and confirming zero retries. Do not hide this
  mutation in ordinary login or initialization paths.
- PIV version 6.0+ exposes unauthenticated token randomness through `00 84`.
  Advertise `CKF_RNG` only after that version check. `C_GenerateRandom` chunks
  requests at 256 bytes; `C_SeedRandom` returns
  `CKR_RANDOM_SEED_NOT_SUPPORTED` because firmware has no seed-injection APDU.
- `CKA_CNK_PIV_PIN_POLICY` and `CKA_CNK_PIV_TOUCH_POLICY` are public
  vendor-defined `CK_BYTE` attributes in `include/pkcs11_canokey.h`. They can
  be supplied on private-key templates for `C_GenerateKeyPair` and
  `C_CreateObject(CKO_PRIVATE_KEY)`, and can be read back through
  `C_GetAttributeValue` from CanoKey metadata. `CKA_ALWAYS_AUTHENTICATE` remains
  a compatibility input for PIN policy when the vendor PIN policy is absent.
- CanoKey PIV default key policies are: slot 9E uses PIN never and touch never;
  other PIV key slots use PIN once and touch never.
- Runtime private-key operations must honor stored PIN policy. PIN-never keys
  can use GENERAL AUTHENTICATE without `CKU_USER`; PIN-once and PIN-always keys
  require a cached user PIN and must verify it before the operation.
- PIV data objects should be exposed as `CKO_DATA` token objects. Enumeration
  uses a fixed table of known PIV data-object candidates and returns only
  objects that `GET DATA` reports as present. The current candidate table covers
  CHUID, cardholder fingerprints, security object, card capability container,
  cardholder facial image, printed information, key history, and discovery
  object. `CKA_OBJECT_ID` uses ASN.1 object-identifier content octets, matching
  OpenSC's `pkcs11-tool --application-id` encoding. Logged-in sessions retry
  PIV data reads with the cached user PIN so PIN-protected data can be
  discovered when present. `C_CreateObject(CKO_DATA)` is the write/overwrite
  path and maps to PIV `PUT DATA`; `C_SetAttributeValue` remains read-only, so
  token PIV objects report `CKA_MODIFIABLE = CK_FALSE`.
- `CKA_CNK_VENDOR_BASE` uses ASCII `CNK` (`0x43 0x4E 0x4B`) in the high bytes
  of the vendor-defined attribute range and reserves the low byte for CanoKey
  attribute IDs.
- CanoKey PIV policy values match `include/key.h` in canokey-core:
  `CNK_PIV_PIN_POLICY_NEVER` = 0x01, `CNK_PIV_PIN_POLICY_ONCE` = 0x02,
  `CNK_PIV_PIN_POLICY_ALWAYS` = 0x03, `CNK_PIV_TOUCH_POLICY_NEVER` = 0x01,
  `CNK_PIV_TOUCH_POLICY_ALWAYS` = 0x02, and
  `CNK_PIV_TOUCH_POLICY_CACHED` = 0x03.
- ECDH, ML-KEM, and host key generation share the session secret-key allocator.
  Session secret keys support copy, secure destroy, restricted label/usage
  updates, and `C_DigestKey` for non-sensitive values. PIV token objects remain
  non-copyable, non-destroyable, and read-only.

RSA signing note:

- CanoKey accepts RSA-sized PIV GENERAL AUTHENTICATE requests through short APDU command chaining.
- CanoKey rejects the equivalent extended APDU form with `6700`.
- OpenSC sends the RSA-2048 request as `10 87 07 9A FF <first 255 bytes>` followed by `00 87 07 9A 0B <last 11 bytes> 00`.

Known-good historical hardware probes after the chaining fix follow. Their
slot IDs no longer match the current key inventory:

```powershell
& 'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe' --module "$PWD\build-ninja-clangcl-x64\canokey-pkcs11.dll" --slot-index 0 --login --pin 123456 --sign --type privkey --id 01 --mechanism SHA256-RSA-PKCS --input-file .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.txt --output-file .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.sha256-rsa-pkcs.sig
& 'C:\Program Files\Git\mingw64\bin\openssl.exe' dgst -sha256 -verify .\build-ninja-clangcl-x64\piv-9a-rsa-test\piv-9a-rsa-pub.pem -signature .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.sha256-rsa-pkcs.sig .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.txt
```

Additional probes that passed:

- `RSA-PKCS` with `openssl pkeyutl -verifyrecover`.
- `SHA256-RSA-PKCS-PSS --salt-len 32` with OpenSSL PSS verification.
- `ECDSA-SHA256 --signature-format openssl` on ID 02 with OpenSSL verification.
- `test_real.exe` built and ran against the current hardware after the
  cross-platform loader/CMake changes. It covered RSA v1.5, RSA-PSS, RSA
  multipart, ECDSA, ECDSA-SHA1, and ECDSA-SHA256 with TF-PSA-Crypto's
  mbedtls-compatible verification APIs.

3DES note:

- PIV management-key authentication still needs 3DES-EDE single-block
  encryption for the card challenge in `cnkVerifyManagementKey()`.
- TF-PSA-Crypto does not provide the old `mbedtls/des.h` API, so the module
  has a narrow internal helper in `src/internal/des.c` instead of depending on
  another crypto library.
- The helper has been checked against the DES known-answer vector
  `133457799BBCDFF1` / `0123456789ABCDEF` -> `85E813540F0AB405` by using the
  same key for all three 3DES keys.

## Running Mode Notes

- For OpenSC and other normal PKCS#11 consumers, run this as a standalone DLL.
- Standalone mode is the default when no caller invokes `C_CNK_EnableManagedMode()` before `C_Initialize()`.
- Managed mode is selected through `C_CNK_EnableManagedMode()` with a non-NULL
  `CNK_MANAGED_MODE_INIT_ARGS` pointer before `C_Initialize()`.
- `C_Initialize()` treats `pInitArgs` as standard PKCS#11
  `CK_C_INITIALIZE_ARGS`; `pReserved` must be NULL and is not a managed-mode
  entry point.
- The `pkcs11-tool --show-info` smoke test reached `C_Initialize` with `pInitArgs == NULL`, so it was using standalone mode.

## Current Implementation Shape

- `src/api/`: exported PKCS#11 and CanoKey extension entry points, including
  initialization, slots, sessions, objects, digesting, signing, host-side
  verification/encryption, card-side decryption, centralized operation cleanup,
  and 3.x compatibility stubs.
- `include/private/api/`: private declarations shared by the API entry-point
  source files.
- `src/backend/`: card/backend integrations. `pcsc.c` handles PC/SC
  reader discovery, PIV AID selection, PIN verify/logout, GET DATA, and GENERAL
  AUTHENTICATE signing, RSA decryption, ECDH, and ML-KEM. `piv_metadata.c`
  handles version-gated metadata, algorithm extensions, and token randomness.
- `include/private/backend/`: private backend-facing declarations.
- `src/internal/`: implementation helpers that are not direct API entry points,
  including logging, mutex wrappers, RSA padding/PSS helpers, ML-DSA/ML-KEM
  wrappers, shared template validation, PIV object wire encoding, TLV utilities,
  and the PIV management-key 3DES block helper.
- `include/private/internal/`: private helper declarations for the internal
  implementation layer.

PIV object IDs map to slots as:

```text
1 -> 9A
2 -> 9C
3 -> 9D
4 -> 9E
5 -> 82
6 -> 83
```

## Known Gaps

- Wrap/unwrap, multipart encrypt/decrypt, PIV token-object delete/set-attribute,
  and init PIN remain unsupported or return the corresponding object-policy
  error. `C_GenerateKey` uses host randomness for session-only AES and
  generic-secret keys, while `C_GenerateRandom` uses the firmware 6.0+ token
  RNG.
- `C_GetObjectSize` is implemented as an approximate PKCS#11 object size based
  on readable attributes. `C_SetAttributeValue` validates object handles but
  treats PIV token attributes as read-only. `C_CopyObject` supports session
  secret keys; PIV token objects do not have stable copy semantics.
- `C_DestroyObject` securely clears session secret keys. CanoKey PIV supports
  PUT DATA (`00 DB`) for certificate writes and a special `53 00` certificate
  delete case, but there is no standard PIV APDU that deletes both certificates
  and asymmetric keys with matching PKCS#11 object semantics.
- Current reader enumeration only keeps PC/SC reader names containing `canokey`, case-insensitive.
- Standalone `C_Initialize()` reads `CNK_LOG_LEVEL` and
  `CNK_UNSAFE_LOG_APDU`. Raw APDU logs require both debug-or-lower log level
  and `CNK_UNSAFE_LOG_APDU=1`.
- Managed mode ignores logging environment variables; callers must use
  `C_CNK_ConfigLogging(level, file, unsafe_log_apdu)`.
- Windows CI and local native MSVC/clang-cl builds do not run unit tests for
  now because `test/unit/CMakeLists.txt` requires `PkgConfig` and `cmocka`,
  which are not installed in that environment.
- `BUILD_REAL_TESTING=ON -DBUILD_UNIT_TESTING=OFF` builds `test_real.exe` on Windows without requiring `PkgConfig`/`cmocka`.
- Destructive real-card write tests in `test_real.exe` are opt-in. Set
  `CNK_RUN_DESTRUCTIVE_REAL_TESTS=1` to exercise `C_GenerateKeyPair` and
  `C_CreateObject(CKO_PRIVATE_KEY)` against ID 06 / slot 83. These tests
  intentionally separate SO-authenticated write sessions from USER-authenticated
  signing sessions.
- `test_pqc.exe` is an explicitly destructive full-matrix hardware test. It
  overwrites IDs 08/09 with Ed25519/X25519 generation and import vectors and
  IDs 23/24 with ML-DSA-65/ML-KEM-768 vectors. Windows CI artifacts include
  this executable so it can be run against the downloaded DLL without a local
  build.
