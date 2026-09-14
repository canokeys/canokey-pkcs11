# libcanokey protocol migration experiment

The first increment replaces the shared short-APDU command-chaining and GET
RESPONSE engine with libcanokey's bounded conversation engine. PIV command
builders, metadata interpretation, authorization, host crypto, and PKCS#11
state remain in C. This is not yet a complete migration to PIV applet factories.

## State and lifetime review before implementation

An adapter invocation owns one Rust conversation, its copied command, and its
zeroizing response storage. It borrows a synchronous C transport callback and
card handle only until return. No Rust object survives a PKCS#11 call.

The caller already owns the PC/SC transaction and token/session reservations:
connect -> begin transaction -> SELECT -> VERIFY/authentication -> dependent
commands -> parse/copy -> end transaction -> disconnect. The adapter must never
SELECT, reconnect, release that transaction, or retry failed transport. It must
not enable 6C correction: retrying a credential or mutation is not authorized.

Conversation transitions are Created -> AwaitingResponse -> Completed/Failed.
Every exit drops the conversation and wipes temporary response bytes. Only a
complete response is copied to C. A short output reports required size, but
must not invite replay of a mutation; existing public API size preflights and
terminal-error rules still apply. A failed intermediate chained command stops
the conversation. I/O errors retain the original PC/SC status. A committed
card write cannot be rolled back by dropping Rust state.

PUBLIC/USER/protected-management/SO authorization and logout/finalize draining
are unchanged: the same C reservations surround the same dependent commands.
Protocol tests cover exact transcripts, continuation, failed chaining, malformed
responses, exhausted budgets, transport failure, and output atomicity. Existing
session/mutex tests and fake-PCSC fuzz tests remain required regression gates.

## Build direction

Cargo.toml pins the Git revision; Cargo.lock locks transitive dependencies.
libcanokey is not a submodule. A private staticlib exposes only the transport
adapter, avoiding the all-applet dispatch enum of the experimental upstream C
ABI. Release uses Rust ThinLTO within Rust and native object sections for final
C linker garbage collection; it does not require matching Clang/Rust LLVM
bitcode versions. There is no Rust DLL to distribute.

The latest stable Rust toolchain is selected intentionally. Standard Windows
MSVC targets support Windows 10 / Server 2016 and newer (ARM64 has its own OS
availability). Static linking does not make std compatible with Windows 7/8.1.
Older Windows support requires a separately validated target or an upstream
alloc/no_std effort; it is not claimed by this experiment.

The support floor follows the [Rust target documentation](https://doc.rust-lang.org/rustc/platform-support.html).
Windows retains the existing dynamic C runtime; this experiment statically
links Rust and its standard library, not every operating-system dependency.
ELF links hide symbols from the Rust archive to avoid exporting/interposing
Rust standard-library symbols inside applications loading several modules.

Full PIV-factory migration will need observed device profiles, cache invalidation,
single-SELECT authentication batches, and per-operation status/rollback review.
Do not put the existing high-level factories inside a C transaction after
VERIFY: their SELECT can reset CanoKey authentication.

## Local validation, 2026-09-14

- Rust stable 1.98.1: nine protocol transcript/failure tests, formatting, and
  strict all-target Clippy passed.
- Windows ClangCL 19.1.5: x86, x64, and ARM64 Debug/Release DLLs built. The
  native x86 and x64 C ABI transcript executables ran successfully. ARM64 was
  cross-built; no native ARM64 runtime result is claimed.
- Debian/Clang: all 12 CTest entries passed, including the C/Rust ABI test,
  session/mutex tests and fake-PCSC fuzz smoke. The same 12 passed with C
  ASan/UBSan and leak detection. Stable Rust code itself is not sanitizer
  instrumented.
- OpenSC loaded the new DLL and enumerated `CanoKey Dev`, slot 0, serial `0`.
  ECDSA raw/SHA1/SHA256 signatures verified; ECDH CKD_NULL and SHA256 KDF
  matched software results. No provisioning or destructive tests were enabled.
- The existing real-card harness reports two RSA software-encryption failures
  on the current RSA-3072 key (invalid public key); other RSA fixed-buffer
  probes also report errors. The identical harness against a rebuilt master
  C backend reproduces these results. This is not a complete crypto acceptance
  pass, and the RSA issue has not been diagnosed by this migration.
- The minidriver master pins PKCS#11 `e004368`, two feature commits ahead of
  PKCS#11 master `63a6f01`, including container-name APIs. Directly substituting
  PKCS#11 master therefore fails to compile those APIs. A build-only harness
  kept the minidriver's pinned dependency and replaced only its identical
  master transport file with this adapter. The resulting x64 Release
  minidriver linked successfully. No registry mapping or driver was installed.
- That matched minidriver is 522752 bytes versus 396800 bytes for its matching
  C-only baseline (+123 KiB). Link maps include `cnk_protocol_run` and exclude
  unused `C_Verify`, `C_Encrypt`, ML-DSA and ML-KEM helpers. Imports contain no
  Rust/libcanokey DLL. Static code is removable, but std/unwind support still
  increases the final artifact.
- GitHub workflows now install stable Rust, test the adapter on existing
  Linux/macOS/Windows jobs, and build all six Windows architecture/configuration
  combinations. Remote GitHub Actions, macOS, native ARM64, Windows propagation,
  and external reviewer runs have not been executed for this local experiment.
