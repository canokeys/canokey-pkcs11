# libcanokey PIV 业务逻辑迁移计划

本文档是 PKCS#11 与平级 `libcanokey` clone 之间的共同迁移计划。每个阶段
必须完成本阶段出口条件后再进入下一阶段。旧 C PIV 实现只在对应路径完成
迁移并通过回归后删除，不保留静默 fallback。

## 目标边界

PKCS#11 保留：

- PC/SC connection、transaction、transport 和 reader 生命周期；
- PKCS#11 session/token/object/cache；
- PIN、management-key 和 PUK 生命周期；
- mechanism、hash、RSA padding、KDF；
- `CK_RV` 映射、Windows 字节序和 provider 映射；
- lock、reservation、logout、finalize 和 rollback。

libcanokey 负责：

- PIV SELECT、VERIFY、GENERAL AUTHENTICATE；
- PIV metadata、certificate、object 和 directory；
- signing、RSA decrypt、ECDH/X25519、ML-KEM；
- management-key authentication；
- certificate/key writes；
- PIV firmware/capability gating；
- PIV TLV、certificate container、chaining 和 card status mapping。

## 阶段 0：稳定 profile 和 context 边界

状态：已完成基础实现，仍需补齐并发和 teardown 回归。

- `PivAccessContext`、context-aware metadata/certificate/sign factory 和 C ABI
  由 libcanokey 提供。
- PKCS#11 token state 持有 immutable `DeviceProfile`、binding epoch 和失效状态。
- profile probe 在完整 PC/SC transaction 中执行；profile 写入 token 前重新检查
  token generation。
- finalize、card reset 和 managed binding change 先阻止新调用，再 drain active
  calls、失效 profile、释放 profile，最后释放 PC/SC binding。
- Rust operation 不得跨 token lock、session close 或 finalize 持有 profile 指针。
- 通用 C operation runner 负责：`start -> command -> SCardTransmit -> advance`，
  并在所有退出路径释放 operation、context、command 和 response。

出口条件：profile probe/invalidation、context teardown、并发 transaction 和
malformed operation 测试通过；metadata transcript 与旧实现一致；Linux、ASan/
UBSan、Windows x86/x64/ARM64 全部通过。

## 阶段 1：metadata、certificate、object reads

状态：metadata typed scalar fields、typed public-key compatibility conversion、
certificate、session-scoped PIV object、metadata-directory 和 container-name reads
已接入；metadata 旧 parser 已删除，剩余是 object/directory regression、跨平台
回归和更广泛的 cache/error-path 验证。

libcanokey API：

```rust
get_metadata_in_context(...)
read_object_in_context(...)
read_certificate_in_context(...)
read_metadata_directory_in_context(...)
read_container_name_in_context(...)
```

PKCS#11 改造：

- `cnk_get_metadata_cached` 使用 libcanokey typed `Metadata`；
- `cnk_get_piv_data_by_tag_with_session` 使用 libcanokey object operation；
- `kscNN`/`kxcNN` 使用 `Certificate` typed result；
- 删除 metadata TLV、certificate `53/70/71/FE`、gzip 和 object-wrapper parser；
- 保留 cache freshness、`CKO_CERTIFICATE` 映射、size query 和 output buffer 语义。

错误映射：

```text
NotFound -> absent-object path / CKR_OBJECT_HANDLE_INVALID
AuthenticationFailed -> CKR_USER_NOT_LOGGED_IN or CKR_PIN_INCORRECT
PinBlocked -> CKR_PIN_LOCKED
InvalidResponse / ProtocolViolation -> CKR_DEVICE_ERROR
UnsupportedFeature -> CKR_FUNCTION_NOT_SUPPORTED
LimitExceeded -> CKR_DATA_LEN_RANGE
```

出口条件：metadata、certificate、PIV data enumeration 不调用旧 C parser；
malformed、duplicate、gzip、missing-object、short-buffer、cache freshness 和
certificate propagation 测试通过。

## 阶段 2：sign

当前进度：RSA/ECDSA/P-521/secp256k1/Ed25519 和 ML-DSA sign 均已切换到
libcanokey 的 selected-context operation；旧 C signing builder 已删除。硬件矩阵
和完整 PIN-policy 回归仍待完成，因此本阶段出口条件尚未满足。

libcanokey 负责 GENERAL AUTHENTICATE、PIV wire format、signature parsing、
DER/P1363/raw result、legacy explicit-Le、chaining 和 card status。

PKCS#11 保留 SignInit/Update/Final、hash、RSA PKCS#1/PSS、ECDSA digest、PIN
policy、mechanism mapping、Windows signature conversion 和 output length query。

固定流程：

```text
C_SignFinal
 -> output preflight without card I/O
 -> token reservation
 -> ensure profile
 -> begin transaction and SELECT PIV
 -> VERIFY only when policy requires
 -> create PivAccessContext
 -> create and drive libcanokey sign operation
 -> convert typed result to PKCS#11/Windows format
 -> wipe and release all state
```

PIN-always 仍由 PKCS#11 管理一次 `CKU_CONTEXT_SPECIFIC` retry；libcanokey 不做
隐式 VERIFY 或 retry。`C_DeriveKey` 等 one-shot operation 对 PIN-always 必须
fail closed。

出口条件：RSA PKCS#1/PSS、ECDSA P-256/P-384/P-521、Ed25519/PQC supported sign、
PIN-never/once/always、legacy explicit-Le、size query 和 too-small tests 通过；
旧 C GENERAL AUTHENTICATE signing builder 删除。

## 阶段 3：decrypt、derive 和 one-shot private operations

当前进度：selected-context 的 raw RSA decrypt、ECDH/X25519 derive、ML-KEM
decapsulation C ABI 已接入 PKCS#11；旧 C private-operation builder 已删除。硬件
字节序、KDF、PIN-policy 和 Windows API 回归仍待完成，因此阶段出口条件仍未满足。

libcanokey 增加：

```rust
decrypt_in_context(...)
derive_in_context(...)
decapsulate_in_context(...)
```

libcanokey 负责 raw RSA、ECDH/X25519、ML-KEM command/response、peer validation
和 bounds；PKCS#11 保留 unpadding/OAEP、CNG/CAPI mapping、KDF、Windows
little-endian conversion 和 session-secret object creation。

出口条件：RSA PKCS#1/OAEP、P-256/P-384/P-521 ECDH、X25519、ML-KEM、PIN-always
ECDH fail-closed、Windows decrypt/derive tests 通过；旧 C decrypt/derive builder
删除。

## 阶段 4：management authentication 和 PIV writes

当前进度：libcanokey 已提供 selected-context management authentication，以及
management-authorized object write、certificate write/delete、key generation/import
工厂；PKCS#11 management authorization、`PUT DATA`
object/certificate 写入、key generation、private material import 和 certificate
delete 已切换到 context mutation，并修复了 lock/status failure cleanup。完整
mutation rollback、并发和硬件回归仍待完成；近期 review 暴露的 transaction
cleanup、typed error mapping 和 generated-key output-length 问题见下方修复记录。

libcanokey 负责 External/Mutual management authentication、algorithm selection、
ADMIN DATA/PRINTED parsing、certificate PUT DATA/delete、PIV data writes、key
generation/import、batch progress 和 typed mutation result。

PKCS#11 保留 role mapping、credential cache、token reservation、cache invalidation、
rollback classification 和 PKCS#11 object/handle changes。

每个 mutation 使用：

```text
validate input
 -> reserve token mutation
 -> one PC/SC transaction
 -> explicit management authorization
 -> dependent write
 -> inspect progress
 -> invalidate affected caches
 -> release reservation
```

operation drop 不代表 rollback。卡上不确定 mutation 必须进入 cache invalidation
和 reprobe 路径。

出口条件：External/Mutual auth、wrong key/challenge、blocked state、certificate
write/delete、key generation/import、partial batch failure、logout/finalize race
和 no-duplicate-management-parser tests 通过。

## 阶段 5：删除旧 C PIV 实现

按迁移完成情况删除：

- `src/backend/piv_metadata.c` 的旧 metadata parser；
- `src/backend/piv_data.c` 的旧 object parser；
- `src/backend/piv_crypto.c` 的旧 sign/decrypt/derive builder；
- `src/backend/piv_auth.c` 的重复 management auth；
- `src/backend/piv_key_write.c` 的重复 write encoding。

最终 C PIV 层只保留 PC/SC transaction helper、transport callback、PKCS#11
authorization/cache/rollback 和 compatibility wrappers。

## 必跑测试矩阵

每个阶段都运行：

- libcanokey workspace tests、C ABI tests、strict Clippy、rustdoc；
- PKCS#11 unit tests、API contract coverage、Linux CTest；
- fake-PCSC transcript tests；
- ASan/UBSan/leak detection；
- Windows x86/x64/ARM64 Debug/Release；
- `git diff --check`。

每个 context operation 必须覆盖：

- 第一条 target APDU 不包含 SELECT；
- SELECT/VERIFY/target 位于同一 PC/SC transaction；
- intermediate failure 不 replay；
- malformed response 不发布 partial result；
- short output 不发送 APDU；
- profile invalidation、close/finalize、card reset race；
- two sessions 的 physical transaction serialization；
- logout 必须撤销尚未开始 card I/O 的 operation context；已经取得 token
  reservation 并进入 card I/O 的 admitted operation 保留 authorization，直到
  card work 和 result commit 完成，随后再清理 context。

硬件验收顺序：metadata enumeration、certificate propagation、ECDSA/RSA sign、
RSA decrypt、ECDH derive、certificate write、key generation/import、reset/reinsert、
native ARM64 propagation。

## PR 和版本策略

libcanokey 与 PKCS#11 使用 stacked PR。每个 PKCS#11 commit 固定 libcanokey
具体 Git revision 并更新 Cargo.lock。只有当前阶段出口条件和 CI 全绿后进入下
一阶段；不得把未迁移的 C fallback 宣称为已完成迁移。

## Review repair checkpoint (2026-09-14)

Reviewed PR #5 comments in reviews 5196542652 and 5197023753 against the code.
The selected-context calls now share a bounded C executor and lock-scoped
profile clone. Failed ABI/transport/parse paths cannot return a stale CKR_OK.
Data reads preserve successful copy results; the shared metadata/generated
public-key encoder reports exact TLV lengths. Profile probes no longer run
inside write transactions. Every attempted mutation invalidates public caches,
including uncertain completion. Certificate deletion rejects read-only sessions
and reports CKA_DESTROYABLE consistently with its implemented behavior.

SO and protected management verification now share the libcanokey authentication
machine used by write authorization. Libcanokey revision d52d1aa preserves legacy
explicit Le without reselecting. Both Cargo dependencies use the same revision.
The C management transcript test covers TDES (1.3/3.0.3) and AES-192 (3.1.0),
transport failure at each exchange, malformed challenges, rejected cryptograms,
mutex failure, and transaction transfer/release. C ABI failure injection covers
PUT DATA, certificate deletion, generation/import, data/name reads, output
queries, exact RSA lengths, obsolete profile epochs and conversation budgets.

This checkpoint does not complete stages 0–5. Remaining acceptance includes
full profile reset/cache-generation races, PIN and protected-object format
migration, configured algorithm IDs, F5 compatibility and attestation naming,
full mutation/concurrency transcripts, and cross-repository/hardware validation.
Legacy management-algorithm metadata and PIN operations still live in C.

Validation for this checkpoint: Windows x86/x64/ARM64 Debug and Release builds
pass; all three C/Rust contract tests run successfully on x86 and x64. Linux
CTest passes 10/10 normally and 10/10 with ASan/UBSan and leak detection.
PKCS#11 Rust adapter tests (9), strict Clippy, and API coverage (118/118) pass.
Libcanokey workspace tests, strict Clippy, rustdoc, and C/C++ ABI transcripts
pass. ARM64 executables were built but not run locally; real-card/minidriver
acceptance and full PR-head CI are separate outstanding checks.

## Review reply checkpoint (2026-09-14)

Audited all 23 PKCS#11 PR #5 threads and all six libcanokey PR #1 threads,
including resolved threads without a reply. The remaining PKCS#11 profile-lifetime
and RSA-length findings are covered by 77d1edd. Libcanokey e71a0b6 fixes the
remaining pre-limit input allocations and documents all 18 unsafe context ABI
entries and all 21 Result-returning Rust context factories/constructors.

Selected streaming input now shares standalone validation (SM2 IDs are absent
or 1..=32 bytes, and other modes reject an ID). Object and certificate writes
reject inputs above max_input_bytes before copying. Allocation-observing Rust
regressions reproduced the original failures and pass after the fix. The C ABI
transcript checks error descriptor validation/clearing and copied inputs surviving
source-profile/context release. Both PKCS#11 Cargo dependencies now pin e71a0b6.
Review replies identify the specific implementation and verification for each
original finding; they do not declare the remaining migration gates complete.

For card calls that acquire a token reservation, successful reservation
acquisition is the admission point: logout returns CKR_OPERATION_ACTIVE while
that reservation protects card I/O and result commit. An initialized operation
context alone is not admission. The existing
`test_logout_cannot_race_protected_management_login` regression checks logout
rejection during both protected login and a held management-operation reservation;
`test_logout_revokes_context_specific_authorization` checks context revocation.
The full physical-card concurrency matrix remains a migration acceptance gate.

The e71a0b6 dependency pin passes Windows x86/x64/ARM64 Debug/Release builds,
x86/x64 C/Rust contract tests, Linux CTest (10/10), ASan/UBSan with leak detection
(10/10), Rust adapter tests (9), strict Clippy and API contract coverage (118/118).
All 29 original inline threads have individual replies. Review-body findings
are answered with links to their source reviews because GitHub does not support
nested replies to review summaries. Native ARM64 execution and hardware
acceptance remain separate from these build and offline-test results.

## Hardware checkpoint (2026-09-14)

Real tests now run on reader `canokeys.org OpenPGP PIV OATH 0`, slot 0,
serial 0, firmware `3.1.0-dev+gaa408988`, PIV 6.0.0. The previous offline
success did not establish hardware interoperability: the first real public-key
enumeration failed before GET METADATA because development suffixes disabled
capabilities. Per the requested policy, libcanokey 4c12441 now uses the declared
numeric base version by default while preserving identity and unknown-version
handling.

Hardware then exposed ordinary-slot ECDH rejection and raw-object framing
incompatibility, repaired by 97f4dab. P-521 responses use nonminimal definite
BER envelope lengths, fixed by f961dc2 while retaining strict DER signature
validation. The C adapter now preserves short digest lengths so P-521 digest
normalization occurs once. It also consumes raw container factories for data
compatibility and directly exposes decoded certificate payloads.

The management key was restored to the documented default at the user's
request and verified by fresh authentication. Test keys were created in
previously empty slots 87 (RSA-2048), 88 (P-521), 89 (X25519), and 8A (Ed25519).
The first three also passed private-key import and exact public-key comparison.
Temporary certificates were written/read/deleted on 87 with the key preserved.

`scripts/hardware-crypto-test.py` records explicit slot/serial/key selections,
independent software verification, exit status, and the tested DLL SHA-256.
The hardware report documents remaining pre-existing key/metadata anomalies
on 9D, 9E, 85 and 86; those slots were not reprovisioned. Hardware successes do
not close the full concurrency, PIN-policy, managed-mode/minidriver or reset
acceptance gates. See `docs/hardware-validation-2026-09-14.md` for the matrix.

Final verification for this hardware checkpoint: x64 Debug and Release each
pass 14/14 selected hardware groups. Windows x86/x64/ARM64 Debug/Release builds
pass; x86/x64 C/Rust contract tests pass. Linux CTest and ASan/UBSan with leak
detection each pass 10/10. Rust adapter tests, strict Clippy, libcanokey workspace
tests, rustdoc and C/C++ ABI tests pass. Native ARM64 execution remains unrun.
