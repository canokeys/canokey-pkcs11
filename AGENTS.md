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

## Development Hygiene

- Before committing C source or header changes, run `clang-format` on the touched `.c` and `.h` files.
- The VS bundled formatter is:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\Llvm\x64\bin\clang-format.exe`
- Commit messages must follow Conventional Commits, include enough detail in the body for non-trivial changes, and use signoff (`git commit -s`).

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

## Real CanoKey Probe Notes

With a CanoKey inserted, `opensc-tool --list-readers` reported:

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
- `MAX_FIND_OBJECTS` is 18 to fit 6 PIV slots x 3 object classes.
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
ID 01 -> slot 9A -> RSA-2048 key and certificate
ID 02 -> slot 9C -> EC P-256 key and certificate
```

Generated test artifacts are under:

```text
build-ninja-clangcl-x64\piv-9a-rsa-test\
build-ninja-clangcl-x64\piv-9c-test\
```

OpenSC's own module is useful as an external comparison point:

```text
C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll
```

RSA signing note:

- CanoKey accepts RSA-sized PIV GENERAL AUTHENTICATE requests through short APDU command chaining.
- CanoKey rejects the equivalent extended APDU form with `6700`.
- OpenSC sends the RSA-2048 request as `10 87 07 9A FF <first 255 bytes>` followed by `00 87 07 9A 0B <last 11 bytes> 00`.

Known-good real-hardware probes after the chaining fix:

```powershell
& 'C:\Program Files\OpenSC Project\OpenSC\tools\pkcs11-tool.exe' --module "$PWD\build-ninja-clangcl-x64\canokey-pkcs11.dll" --slot-index 0 --login --pin 123456 --sign --type privkey --id 01 --mechanism SHA256-RSA-PKCS --input-file .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.txt --output-file .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.sha256-rsa-pkcs.sig
& 'C:\Program Files\Git\mingw64\bin\openssl.exe' dgst -sha256 -verify .\build-ninja-clangcl-x64\piv-9a-rsa-test\piv-9a-rsa-pub.pem -signature .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.sha256-rsa-pkcs.sig .\build-ninja-clangcl-x64\piv-9a-rsa-test\rsa-message.txt
```

Additional probes that passed:

- `RSA-PKCS` with `openssl pkeyutl -verifyrecover`.
- `SHA256-RSA-PKCS-PSS --salt-len 32` with OpenSSL PSS verification.
- `ECDSA-SHA256 --signature-format openssl` on ID 02 with OpenSSL verification.
- `test_real.exe` built and ran against the current hardware after the cross-platform loader/CMake changes. It covered RSA v1.5, RSA-PSS, RSA multipart, ECDSA, ECDSA-SHA1, and ECDSA-SHA256 with mbedTLS verification.

## Running Mode Notes

- For OpenSC and other normal PKCS#11 consumers, run this as a standalone DLL.
- Standalone mode is the default when no caller invokes `C_CNK_EnableManagedMode()` before `C_Initialize()`.
- The README says managed mode is selected via non-null `pReserved`, but the current code actually uses the `C_CNK_EnableManagedMode()` extension to set `g_cnk_is_managed_mode`.
- The `pkcs11-tool --show-info` smoke test reached `C_Initialize` with `pInitArgs == NULL`, so it was using standalone mode.

## Current Implementation Shape

- `src/pkcs11_core.c`: PKCS#11 initialization/finalization, exported function list, standalone PC/SC init.
- `src/pcsc_backend.c`: PC/SC reader discovery, PIV AID selection, PIN verify/logout, GET DATA, metadata, GENERAL AUTHENTICATE signing.
- `src/pkcs11_slot.c`: slot/token info and mechanism list/info.
- `src/pkcs11_session.c`: session table, login/logout, PIN caching per session.
- `src/pkcs11_object.c`: virtual PIV object handles, object discovery, and partial attribute retrieval.
- `src/pkcs11_signing.c`: RSA PKCS#1 v1.5/PSS and ECDSA signing path.
- `src/pkcs11_digesting.c`: SHA/SHA3 digest support through mbedTLS.

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

- Encryption/decryption, verify, key generation, random generation, wrap/unwrap/derive, object create/delete/set-attribute, init/set PIN, and slot events are mostly stubs returning `CKR_FUNCTION_NOT_SUPPORTED`.
- Current reader enumeration only keeps PC/SC reader names containing `canokey`, case-insensitive.
- Debug builds define `CNK_VERBOSE`; `C_Initialize()` forces debug logging unless later changed through `C_CNK_ConfigLogging()`, so `pkcs11-tool` output is noisy.
- `BUILD_UNIT_TESTING=ON` with the Windows native MSVC/clang-cl toolchain currently fails before compiling unit tests because `test/unit/CMakeLists.txt` requires `PkgConfig`/`cmocka`.
- `BUILD_REAL_TESTING=ON -DBUILD_UNIT_TESTING=OFF` builds `test_real.exe` on Windows without requiring `PkgConfig`/`cmocka`.
- `test/real/test_real.c` still mostly prints per-case failures instead of accumulating an overall failing exit status, so keep treating it as a hardware diagnostic until it has stricter result accounting.
