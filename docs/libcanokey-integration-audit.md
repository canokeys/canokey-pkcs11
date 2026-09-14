# PIV integration audit: size, diagnostics and minidriver

## Measured binaries

Measurements use Windows native x64 Release and section garbage collection.
The comparable minidriver baseline was rebuilt against its pinned PKCS#11
`e004368`; the upgrade uses the same minidriver source with the logging fix and
the current PKCS#11 branch. The minidriver submodule itself remains unchanged.

| Artifact | Bytes | KiB |
| --- | ---: | ---: |
| PKCS#11 before this audit | 1,026,560 | 1,002.5 |
| PKCS#11 with effective PIV-only ABI and diagnostics | 1,010,688 | 987.0 |
| Minidriver baseline, old PKCS#11 | 396,800 | 387.5 |
| Minidriver with updated PKCS#11 and logging fix | 908,800 | 887.5 |

The original PKCS#11 file contained 814,390 bytes of text and 180,428 bytes of
read-only data. It is not an embedded-PDB problem: only 118 PKCS#11 functions
are exported, and /OPT:REF, /OPT:ICF and Rust ThinLTO were already enabled.
Approximate linker-map attribution includes 146 KiB of Rust PIV code, 96 KiB of
C ABI machinery, 108 KiB of TF-PSA code, 81 KiB of C PQ crypto, and RustCrypto
curve validation, std/unwinding and decompression. These figures are approximate
symbol/object spans, not disjoint audited dependency closures.

The previously nominal `piv` feature retained OATH/OpenPGP erased-operation
variants. Libcanokey `8f23be9` gates optional applet factories and those variants.
The resulting map has no OATH/OpenPGP references, but the net saving is only
15.5 KiB: the required PIV/curve/host-crypto code is the main size cost.

## Error and logging flow

Rust operations return an owned Error with kind, phase, optional status word,
credential reference and optional retries. Constructors copy failures into the
caller's CnkError; failed start/advance also retain the error in the operation.
`cnk_operation_error` can retrieve it before free. Binding/state/panic failures
also have a separate C ABI return status. There is no global/thread-local last
error and no borrowed diagnostic string crossing the ABI.

The C backend maps these details to CK_RV and logs through the PKCS#11 sink.
Profile probing now uses that same executor instead of a separate callback loop
which discarded error details. The diagnostic formatter handles non-protocol
ABI failures too, prints symbolic names and distinguishes absent SW/retries.
An actual Release read of the anomalous slot 86 produced:

```text
ABI=ProtocolError (5), kind=UnexpectedStatusWord (16), phase=Command (2),
reference=None (0), SW=6900, retries=absent
```

These are structured categories, not a complete Rust backtrace or byte-offset
explanation. Parser failures can have no SW even after a successful 9000 response.
Explicit DEBUG/APDU logs work in Release; CNK_VERBOSE/CMD_VERBOSE call/return
tracing is compiled into Debug. Raw APDU data additionally requires the sensitive
logging flag. Tests containing credentials used that flag disabled.

In managed mode, the minidriver passes its registry-derived level, FILE stream
and sensitive flag via C_CNK_ConfigLogging. Rust itself owns no log file. The
minidriver translates CK_RV to the Windows result while the richer detail remains
in that shared log stream.

## Contracts checked at the integration boundary

| Library contract | Consumer requirement / resolution |
| --- | --- |
| Contexts copy a profile and assert caller-established card state; they do not select/authenticate | C retains one card transaction through authorization and the dependent operation |
| Normalized object reads return the outer container value | Raw PKCS#11 data APIs use the explicit container-preserving factory |
| Certificate reads return unwrapped/decompressed payloads | C_GetAttributeValue and cardmod copy that payload without a second TLV parser |
| Digest input is normalized by libcanokey | C preserves short digest length, preventing a second P-521 shift |
| PIV response envelope is definite BER; EC signature encoding is DER | P-521 nonminimal BER lengths are accepted; signature DER remains checked |
| Slot names do not imply the consumer's usage policy | Ordinary-slot agreement supports PKCS#11; Windows still exposes its narrower mapped set |
| Cancellation/drop performs no I/O or rollback | C owns cleanup, cache invalidation and uncertain-write handling |

Rustdoc now describes the context factories' ownership, representations, Safety
and Errors contracts; tests cover the repaired cases. This is not an exhaustive
conformance guarantee. The migration still has explicit gates for full PIN-policy,
reset, concurrency and cross-repository behavior. In particular, F5 attestation
reference compatibility is still a known consumer/interface gap outside this
minidriver's six-slot view.

## Actual minidriver verification

A direct DLL host used the inserted CanoKey through real PC/SC without changing
Calais or installing a driver. It tested two sequential CARD_DATA lifecycles,
`cmapfile`, certificate reads parsed by Windows CryptoAPI, USER authentication,
and signatures in containers 0, 1 and 4 verified by Windows BCrypt.

The audit found a logging lifecycle bug: first-context PKCS#11 log count 129,
second-context count 0. Final C_Finalize resets PKCS#11 logging, while the
minidriver FILE stream survives until DLL unload. Rebinding before each
C_Initialize fixes this. Both cycles then had 129 records, or 132 when the
certificate checks were included. A separate public-read run with raw logging
enabled produced 122 APDU command records; normal credential tests produced zero.

The minidriver workspace contains the rebind fix and `tests/ddi-smoke.c`; its
optional CMake target is CMD_BUILD_DDI_TESTS. The test uses a private volatile
HKCU fixture and process-local HKLM redirection during DLL loading, so machine
settings are not overwritten. Its test artifacts are under the minidriver's
`out/validation/libcanokey-28406d3` directory.

This proves the tested x64 DDI path and log lifecycle. It does not establish
installed Base CSP/KSP or CertPropSvc certificate propagation, native ARM64
runtime behavior, or all container/crypto combinations. The existing card's
9D/9E/85/86 anomalies remain relevant; see the separate hardware report.
