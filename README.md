# canokey-pkcs11

This a PKCS#11 module that allows applications to leverage the PIV applet on CanoKeys.

This module is based on version 2.40 of the PKCS#11 (Cryptoki) specifications. The complete specifications are available at [oasis-open.org](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html).

It uses PCSCLite on Linux, PCSC Framework on macOS, and native PC/SC APIs (`winscard`) on Windows.

## Building

It could be built with CMake on Linux / Windows / macOS using `clang` (Linux / macOS) or `clang-cl` (Windows).
GCC should be supported, but is not tested.

1. Install Dependencies:

```bash
apt-get install -y clang cmake libpcsclite-dev libcmocka-dev ninja-build # Linux only
brew install cmake cmocka ninja-build # macOS only
```

2. Configure and build:

```bash
CC=clang cmake -B build -DCMAKE_BUILD_TYPE=Debug -G Ninja -DENABLE_TESTING=ON . # Linux / macOS
cmake -B build -DCMAKE_BUILD_TYPE=Debug -G "Visual Studio 17 2022" -T ClangCL -A x64 # Windows
cmake --build build -v
```

3. Run tests (Linux / macOS only):

```bash
ctest --test-dir build --output-on-failure # for unit tests
./build/test/real/test_foo ./build/libcanokey-pkcs11.so # test with real PC/SC hardware (for macOS using .dylib)
```

## Running Modes

This module can be run in two modes, namely managed mode and standalone mode.

Standalone mode is the default. In standalone mode, the module manages PC/SC
contexts and sessions by itself. This is the normal mode when used as a plugin
for applications like OpenSC, GnuPG, etc.

Managed mode must be enabled explicitly before `C_Initialize()` by calling
`C_CNK_EnableManagedMode()` with a non-NULL `CNK_MANAGED_MODE_INIT_ARGS`
pointer. The managed-mode arguments provide the PC/SC context, card handle, and
helper functions such as memory allocation callbacks. This mode is mainly used
by CanoKey minidriver for Windows.

`C_Initialize()` no longer uses `pInitArgs->pReserved` to enter managed mode.
Its `pInitArgs` parameter is treated as the standard PKCS#11
`CK_C_INITIALIZE_ARGS` pointer, and `pReserved` must be NULL as required by the
PKCS#11 specification.

## Logging

In standalone mode, logging is configured during `C_Initialize()` from
environment variables:

- `CNK_LOG_LEVEL`: one of `trace`, `debug`, `info`, `warn`, `error`, `fatal`,
  `none`, or the corresponding numeric log level. The default is `warn`.
- `CNK_UNSAFE_LOG_APDU`: set to `1`, `true`, `yes`, or `on` to print raw APDU
  command and response bytes. This is disabled by default because APDUs can
  contain PINs, decrypted plaintext, ECDH shared secrets, management-key
  material, and other sensitive data.

Raw APDU logging also requires the normal log level to include debug messages,
for example:

```bash
CNK_LOG_LEVEL=debug CNK_UNSAFE_LOG_APDU=1 pkcs11-tool --module ./libcanokey-pkcs11.so --show-info
```

In managed mode, environment variables are ignored. The caller should use
`C_CNK_ConfigLogging(level, file, unsafe_log_apdu)` to configure logging and to
decide whether raw APDU bytes are printed.

## CanoKey Extensions

`include/pkcs11_canokey.h` exposes CanoKey-specific PKCS#11 extensions. The
vendor-defined attribute base uses ASCII `CNK` (`0x43 0x4E 0x4B`) in the
vendor-defined attribute range.

The private-key templates for `C_GenerateKeyPair` and
`C_CreateObject(CKO_PRIVATE_KEY)` may include these `CK_BYTE` attributes:

- `CKA_CNK_PIV_PIN_POLICY`: `CNK_PIV_PIN_POLICY_NEVER`,
  `CNK_PIV_PIN_POLICY_ONCE`, or `CNK_PIV_PIN_POLICY_ALWAYS`.
- `CKA_CNK_PIV_TOUCH_POLICY`: `CNK_PIV_TOUCH_POLICY_NEVER`,
  `CNK_PIV_TOUCH_POLICY_ALWAYS`, or `CNK_PIV_TOUCH_POLICY_CACHED`.

If `CKA_CNK_PIV_PIN_POLICY` is absent, `CKA_ALWAYS_AUTHENTICATE` is still
accepted as a compatibility input for the PIN policy. Without either attribute,
CanoKey PIV defaults are used: 9E uses PIN never and touch never, while the
other PIV key slots use PIN once and touch never. The stored policy values can
be read back from public or private PIV key objects with
`C_GetAttributeValue`.

Private-key operations honor the stored PIN policy. Keys with PIN policy never
can sign, decrypt, or derive without `CKU_USER` login; keys with PIN policy once
or always require a logged-in user PIN before the operation.
