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

If `pInitArgs->pReserved` is not NULL, the module is in managed mode.
The module will try to use `pReserved` as a pointer to a `struct CNK_INIT_ARGS`, which provides the PC/SC context and other helper functions (e.g. memory management, logging). This mode is mainly used by CanoKey minidriver for Windows.

Otherwise, the module is in standalone mode. It would manage PC/SC contexts and sessions by itself. This is the default mode when used as plugin for applications like OpenSC, GnuPG, etc.
