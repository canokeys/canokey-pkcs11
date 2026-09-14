"""Windows real-card PKCS#11 checks using cryptography for independent verification.

Requires cryptography, CNK_PIV_PIN, and explicit slot/serial/key selections.
Certificate testing is opt-in and requires CNK_PIV_MANAGEMENT_KEY. It refuses
an existing certificate, deletes its test certificate, and checks key retention.
Explicit --replace-import-* / --replace-generate-* options overwrite a selected
certificate-free test slot and verify its public key and private operations.
Opaque PKCS#11 structures use Windows packing; template storage stays alive
through each borrowed C call. Credentials and shared secrets are never printed.
"""

import argparse
import ctypes as C
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils, x25519, ed25519

U = C.c_ulong
B = C.c_ubyte
P = C.c_void_p


class Attr(C.Structure):
    _pack_ = 1
    _fields_ = [("type", U), ("value", P), ("len", U)]


class Mech(C.Structure):
    _pack_ = 1
    _fields_ = [("type", U), ("param", P), ("len", U)]


class ECDH(C.Structure):
    _pack_ = 1
    _fields_ = [("kdf", U), ("shared_len", U), ("shared", P), ("public_len", U), ("public", P)]


class OAEP(C.Structure):
    _pack_ = 1
    _fields_ = [("hash", U), ("mgf", U), ("source", U), ("len_ptr", P), ("len", U)]


class PSS(C.Structure):
    _pack_ = 1
    _fields_ = [("hash", U), ("mgf", U), ("salt", U)]


RSA_BITS = {"rsa": 2048, "rsa3072": 3072, "rsa4096": 4096}
KEY_KINDS = [*RSA_BITS, "p521", "x25519", "ed25519"]

parser = argparse.ArgumentParser(
    description="Verify explicitly selected keys through a Windows PKCS11 DLL and independent software crypto."
)
parser.add_argument("--module", type=Path, required=True)
parser.add_argument("--slot", type=lambda x: int(x, 0), required=True)
parser.add_argument("--serial", required=True)
for option in ["ecdsa-id", "eddsa-id", "derive-id", "rsa-id"]:
    parser.add_argument("--" + option, type=lambda x: int(x, 16), action="append", default=[])
for option in ["mldsa-id", "mlkem-id", "certificate-id"]:
    parser.add_argument("--" + option, type=lambda x: int(x, 16))
for operation in ["import", "generate"]:
    for kind in KEY_KINDS:
        parser.add_argument(
            "--replace-" + operation + "-" + kind + "-id",
            type=lambda x: int(x, 16),
            help="Overwrite this certificate-free test slot using " + operation + " for " + kind,
        )
parser.add_argument(
    "--name-slot",
    type=lambda x: int(x, 16),
    action="append",
    default=[],
    help="Read/write/restore the name of this physical PIV slot; no key or certificate is changed",
)
parser.add_argument(
    "--pin-managed-unconfigured",
    action="store_true",
    help="Verify unconfigured PIN-managed login is rejected and its USER login is rolled back",
)
parser.add_argument("--report", type=Path)
args = parser.parse_args()
if os.name != "nt":
    parser.error("This ctypes layout targets native Windows only")
if "CNK_PIV_PIN" not in os.environ:
    parser.error("CNK_PIV_PIN is required")
imports = [(kind, getattr(args, "replace_import_" + kind + "_id")) for kind in KEY_KINDS]
generations = [(kind, getattr(args, "replace_generate_" + kind + "_id")) for kind in KEY_KINDS]
if (
    args.certificate_id is not None
    or args.name_slot
    or any(id is not None for _, id in imports + generations)
) and "CNK_PIV_MANAGEMENT_KEY" not in os.environ:
    parser.error("Card write tests require CNK_PIV_MANAGEMENT_KEY")
if (args.mldsa_id is None) != (args.mlkem_id is None):
    parser.error("Specify both --mldsa-id and --mlkem-id")
args.module = args.module.resolve()
os.environ["CNK_UNSAFE_LOG_APDU"] = "0"
lib = C.CDLL(str(args.module))


class Version(C.Structure):
    _pack_ = 1
    _fields_ = [("major", B), ("minor", B)]


class SessionInfo(C.Structure):
    _pack_ = 1
    _fields_ = [("slot", U), ("state", U), ("flags", U), ("device_error", U)]


class TokenInfo(C.Structure):
    _pack_ = 1
    _fields_ = (
        [("label", B * 32), ("manufacturer", B * 32), ("model", B * 16), ("serial", B * 16), ("flags", U)]
        + [
            (n, U)
            for n in [
                "max_sessions",
                "sessions",
                "max_rw_sessions",
                "rw_sessions",
                "max_pin",
                "min_pin",
                "total_public",
                "free_public",
                "total_private",
                "free_private",
            ]
        ]
        + [("hardware", Version), ("firmware", Version), ("utc", B * 16)]
    )


for name, types in {
    "C_GetTokenInfo": [U, C.POINTER(TokenInfo)],
    "C_GetSessionInfo": [U, C.POINTER(SessionInfo)],
    "C_GetSlotList": [B, C.POINTER(U), C.POINTER(U)],
    "C_CreateObject": [U, C.POINTER(Attr), U, C.POINTER(U)],
    "C_Initialize": [P],
    "C_Finalize": [P],
    "C_OpenSession": [U, U, P, P, C.POINTER(U)],
    "C_CloseSession": [U],
    "C_CNK_LoginPinManaged": [U, P, U],
    "C_Login": [U, U, P, U],
    "C_Logout": [U],
    "C_GetAttributeValue": [U, U, C.POINTER(Attr), U],
    "C_FindObjectsInit": [U, C.POINTER(Attr), U],
    "C_FindObjects": [U, C.POINTER(U), U, C.POINTER(U)],
    "C_FindObjectsFinal": [U],
    "C_VerifyInit": [U, C.POINTER(Mech), U],
    "C_Verify": [U, P, U, P, U],
    "C_EncapsulateKey": [U, C.POINTER(Mech), U, C.POINTER(Attr), U, P, C.POINTER(U), C.POINTER(U)],
    "C_DecapsulateKey": [U, C.POINTER(Mech), U, C.POINTER(Attr), U, P, U, C.POINTER(U)],
    "C_SignInit": [U, C.POINTER(Mech), U],
    "C_Sign": [U, P, U, P, C.POINTER(U)],
    "C_DecryptInit": [U, C.POINTER(Mech), U],
    "C_Decrypt": [U, P, U, P, C.POINTER(U)],
    "C_DeriveKey": [U, C.POINTER(Mech), U, C.POINTER(Attr), U, C.POINTER(U)],
    "C_DestroyObject": [U, U],
    "C_GenerateKeyPair": [
        U,
        C.POINTER(Mech),
        C.POINTER(Attr),
        U,
        C.POINTER(Attr),
        U,
        C.POINTER(U),
        C.POINTER(U),
    ],
    "C_GenerateRandom": [U, P, U],
    "C_CNK_GetContainerName": [U, B, P, C.POINTER(U)],
    "C_CNK_SetContainerName": [U, B, P, U],
}.items():
    f = getattr(lib, name)
    f.argtypes = types
    f.restype = U


def check(rv):
    if rv:
        raise RuntimeError(f"PKCS11 error 0x{rv:x}")


def attrs(values):
    storage = [C.create_string_buffer(v) if isinstance(v, bytes) else U(v) for _, v in values]
    return (
        (Attr * len(values))(
            *[
                Attr(t, C.cast(C.pointer(v), P), len(raw) if isinstance(raw, bytes) else C.sizeof(U))
                for (t, raw), v in zip(values, storage)
            ]
        ),
        storage,
    )


s = U()


def attr(key, t):
    a = Attr(t, None, 0)
    check(lib.C_GetAttributeValue(s, key, C.byref(a), 1))
    if a.len > 8192:
        raise RuntimeError("Attribute exceeds hardware-test buffer limit")
    b = C.create_string_buffer(a.len)
    a.value = C.cast(b, P)
    check(lib.C_GetAttributeValue(s, key, C.byref(a), 1))
    return b.raw[: a.len]


def find(cls, id):
    a, keep = attrs([(0, cls), (258, bytes([id]))])
    check(lib.C_FindObjectsInit(s, a, len(a)))
    try:
        result = (U * 4)()
        n = U()
        check(lib.C_FindObjects(s, result, 4, C.byref(n)))
        return list(result[: n.value])
    finally:
        check(lib.C_FindObjectsFinal(s))


def key_for(cls, id):
    keys = find(cls, id)
    if len(keys) != 1:
        raise RuntimeError(f"Expected exactly one class {cls} key with ID {id:02x}; found {len(keys)}")
    return keys[0]


def public(id):
    key = key_for(2, id)
    kind = int.from_bytes(attr(key, 256), "little")
    if kind == 0:
        return rsa.RSAPublicNumbers(
            int.from_bytes(attr(key, 290), "big"), int.from_bytes(attr(key, 288), "big")
        ).public_key()
    if kind == 3:
        params = attr(key, 384)
        curve = {
            bytes.fromhex("06082a8648ce3d030107"): ec.SECP256R1,
            bytes.fromhex("06052b81040022"): ec.SECP384R1,
            bytes.fromhex("06052b81040023"): ec.SECP521R1,
        }[params]()
        point = attr(key, 385)
        start = 2 if point[1] < 128 else 2 + (point[1] & 127)
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point[start:])
    if kind == 64:
        return ed25519.Ed25519PublicKey.from_public_bytes(attr(key, 385))
    if kind == 65:
        return x25519.X25519PublicKey.from_public_bytes(attr(key, 385))
    raise RuntimeError(f"unsupported kind {kind}")


def login(role, key):
    check(lib.C_Login(s, role, key, len(key)))


def sign(id, mechanism, data):
    key = key_for(3, id)
    check(lib.C_SignInit(s, C.byref(mechanism), key))
    n = U()
    check(lib.C_Sign(s, data, len(data), None, C.byref(n)))
    out = C.create_string_buffer(n.value)
    short = U(1)
    if not lib.C_Sign(s, data, len(data), out, C.byref(short)) == 336:
        raise AssertionError("Hardware check failed")
    if not short.value == n.value:
        raise AssertionError("Hardware check failed")
    check(lib.C_Sign(s, data, len(data), out, C.byref(n)))
    return out.raw[: n.value]


def derive(id):
    pub = public(id)
    if isinstance(pub, x25519.X25519PublicKey):
        peer = x25519.X25519PrivateKey.generate()
        encoded = peer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        expected = peer.exchange(pub)
    else:
        peer = ec.generate_private_key(pub.curve)
        encoded = peer.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        expected = peer.exchange(ec.ECDH(), pub)
    buf = C.create_string_buffer(encoded)
    params = ECDH(1, 0, None, len(encoded), C.cast(buf, P))
    m = Mech(4176, C.cast(C.pointer(params), P), C.sizeof(params))
    a, keep = attrs(
        [(0, 4), (256, 16), (353, len(expected)), (1, b"\x00"), (2, b"\x01"), (259, b"\x00"), (354, b"\x01")]
    )
    h = U()
    check(lib.C_DeriveKey(s, C.byref(m), key_for(3, id), a, len(a), C.byref(h)))
    actual = attr(h, 17)
    check(lib.C_DestroyObject(s, h))
    if not actual == expected:
        raise AssertionError("Hardware and software shared secrets differ")
    print(f"PASS ECDH/X25519 id={id:02x} {len(actual)} bytes", flush=True)


def rsa_checks(id):
    pub = public(id)
    if not pub.public_numbers().n & 1:
        raise AssertionError("pre-existing RSA modulus is even")
    msg = b"CanoKey real hardware verification 2026-09-14"
    for pss in [False, True]:
        params = PSS(592, 2, 32)
        m = Mech(
            67 if pss else 64, C.cast(C.pointer(params), P) if pss else None, C.sizeof(params) if pss else 0
        )
        sig = sign(id, m, msg)
        pad = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32) if pss else padding.PKCS1v15()
        pub.verify(sig, msg, pad, hashes.SHA256())
        print("PASS RSA SHA256", "PSS" if pss else "PKCS1", flush=True)
    for oaep in [False, True]:
        pad = (
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            if oaep
            else padding.PKCS1v15()
        )
        ct = pub.encrypt(msg, pad)
        params = OAEP(592, 2, 1, None, 0)
        m = Mech(
            9 if oaep else 1, C.cast(C.pointer(params), P) if oaep else None, C.sizeof(params) if oaep else 0
        )
        check(lib.C_DecryptInit(s, C.byref(m), key_for(3, id)))
        n = U()
        check(lib.C_Decrypt(s, ct, len(ct), None, C.byref(n)))
        out = C.create_string_buffer(n.value)
        check(lib.C_Decrypt(s, ct, len(ct), out, C.byref(n)))
        if not out.raw[: n.value] == msg:
            raise AssertionError("Hardware check failed")
        print("PASS RSA decrypt", "OAEP-SHA256" if oaep else "PKCS1", flush=True)


def pqc_checks():
    msg = b"Actual CanoKey ML-DSA verification"
    m = Mech(29, None, 0)
    sig = sign(args.mldsa_id, m, msg)
    check(lib.C_VerifyInit(s, C.byref(m), key_for(2, args.mldsa_id)))
    check(lib.C_Verify(s, msg, len(msg), sig, len(sig)))
    if not len(sig) == 3309:
        raise AssertionError("Hardware check failed")
    print("PASS ML-DSA-65 hardware sign / host verify", flush=True)
    m = Mech(23, None, 0)
    a, keep = attrs([(259, b"\x00"), (354, b"\x01"), (353, 32)])
    ct = C.create_string_buffer(1088)
    n = U(1088)
    host = U()
    card = U()
    check(
        lib.C_EncapsulateKey(
            s, C.byref(m), key_for(2, args.mlkem_id), a, len(a), ct, C.byref(n), C.byref(host)
        )
    )
    try:
        check(lib.C_DecapsulateKey(s, C.byref(m), key_for(3, args.mlkem_id), a, len(a), ct, n, C.byref(card)))
        if not attr(host, 17) == attr(card, 17):
            raise AssertionError("Hardware check failed")
        print("PASS ML-KEM-768 host encapsulate / hardware decapsulate", flush=True)
    finally:
        if card.value:
            check(lib.C_DestroyObject(s, card))
        check(lib.C_DestroyObject(s, host))


def certificate_checks():
    id = args.certificate_id
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from datetime import datetime, timedelta, timezone

    if not not find(1, id):
        raise AssertionError("Refusing to overwrite an existing certificate")
    before = public(id).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CanoKey hardware test")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public(id))
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .sign(issuer, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
    a, keep = attrs([(0, 1), (128, 0), (258, bytes([id])), (1, b"\x01"), (17, certificate)])
    handle = U()
    check(lib.C_CreateObject(s, a, len(a), C.byref(handle)))
    try:
        if not attr(handle, 17) == certificate:
            raise AssertionError("Hardware check failed")
        if not find(1, id) == [handle.value]:
            raise AssertionError("Hardware check failed")
        print("PASS certificate write/read byte equality", flush=True)
    finally:
        check(lib.C_DestroyObject(s, handle))
    if not not find(1, id):
        raise AssertionError("Hardware check failed")
    if (
        not public(id).public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        == before
    ):
        raise AssertionError("Hardware check failed")
    print("PASS certificate delete preserves public key", flush=True)
    check(lib.C_Logout(s))


def ecdsa_checks(id):
    pub = public(id)
    for algorithm in [hashes.SHA256(), hashes.SHA512()]:
        digest = hashes.Hash(algorithm)
        digest.update(b"CanoKey hardware ECDSA verification")
        data = digest.finalize()
        sig = sign(id, Mech(4161, None, 0), data)
        width = (pub.key_size + 7) // 8
        if not len(sig) == 2 * width:
            raise AssertionError("Wrong ECDSA signature length")
        encoded = utils.encode_dss_signature(
            int.from_bytes(sig[:width], "big"), int.from_bytes(sig[width:], "big")
        )
        pub.verify(encoded, data, ec.ECDSA(utils.Prehashed(algorithm)))
        print(f"PASS ECDSA ID {id:02x}, {pub.key_size} bits, {algorithm.name}", flush=True)


def eddsa_checks(id):
    message = b"CanoKey Ed25519 hardware verification"
    signature = sign(id, Mech(0x1057, None, 0), message)
    public(id).verify(signature, message)
    print(f"PASS Ed25519 ID {id:02x}, independent software verification", flush=True)


def random_check():
    output = C.create_string_buffer(1024)
    check(lib.C_GenerateRandom(s, output, len(output)))
    if not len(set(output.raw)) > 200:
        raise AssertionError("Degenerate hardware random output")


results = []


def run_case(name, operation):
    try:
        operation()
        results.append({"name": name, "status": "pass"})
    except Exception as error:
        detail = f"{type(error).__name__}: {error}"
        results.append({"name": name, "status": "fail", "detail": detail})
        print(f"FAIL {name}: {detail}", flush=True)


def unconfigured_management_check():
    pin = os.environ["CNK_PIV_PIN"].encode()
    if lib.C_CNK_LoginPinManaged(s, pin, len(pin)) != 0x20:
        raise RuntimeError("PIN-managed login did not report an unconfigured policy")
    info = SessionInfo()
    check(lib.C_GetSessionInfo(s, C.byref(info)))
    if info.state != 2:
        raise RuntimeError("Unconfigured PIN-managed login did not restore the public session")
    print("PASS unconfigured PIN-managed login and USER-state rollback", flush=True)


def names_checks(slots):
    def get(slot):
        length = U()
        check(lib.C_CNK_GetContainerName(s, slot, None, C.byref(length)))
        if length.value > 78:
            raise RuntimeError("Container name exceeds the public API limit")
        output = C.create_string_buffer(length.value)
        check(lib.C_CNK_GetContainerName(s, slot, output, C.byref(length)))
        return output.raw[: length.value]

    valid_slots = {0x9A, 0x9C, 0x9D, 0x9E, 0xF9, *range(0x82, 0x96)}
    if not slots or len(set(slots)) != len(slots) or any(slot not in valid_slots for slot in slots):
        raise RuntimeError("Select valid, distinct physical PIV references for name testing")
    originals = {slot: get(slot) for slot in slots}
    length = U()
    if lib.C_CNK_GetContainerName(s, 0xF9, None, C.byref(length)) not in (0, 0x60):
        raise RuntimeError("F9 name query lost its valid-reference/absent-key distinction")
    name = ("cnk-" + uuid.uuid4().hex[:20] + "-\U0001f511").encode("utf-16le")
    if lib.C_CNK_SetContainerName(s, slots[0], name, 1) != 0x20:
        raise RuntimeError("Malformed UTF-16 was not rejected before authentication")
    if lib.C_CNK_SetContainerName(s, slots[0], name, len(name)) != 0x101:
        raise RuntimeError("Public name write did not require management authorization")
    login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
    attempted = []
    try:
        attempted.append(slots[0])
        check(lib.C_CNK_SetContainerName(s, slots[0], name, len(name)))
        if get(slots[0]) != name:
            raise RuntimeError("Name read differs from its UTF-16 write")
        output = C.create_string_buffer(b"\xcc" * 80)
        length = U(1)
        if lib.C_CNK_GetContainerName(s, slots[0], output, C.byref(length)) != 0x150:
            raise RuntimeError("Short name buffer did not report CKR_BUFFER_TOO_SMALL")
        if length.value != len(name) or output.raw[:80] != b"\xcc" * 80:
            raise RuntimeError("Short name buffer changed output or returned the wrong length")
        if len(slots) > 1:
            attempted.append(slots[1])
            if lib.C_CNK_SetContainerName(s, slots[1], name, len(name)) != 0x20:
                raise RuntimeError("Duplicate name did not retain CKR_DATA_INVALID")
            if get(slots[1]) != originals[slots[1]]:
                raise RuntimeError("Rejected duplicate changed the other name")
        check(lib.C_CNK_SetContainerName(s, slots[0], None, 0))
        if get(slots[0]) != b"":
            raise RuntimeError("Name clear did not remove the name")
    finally:
        failures = []
        for slot in reversed(attempted):
            try:
                old = originals[slot]
                check(lib.C_CNK_SetContainerName(s, slot, old, len(old)))
                if get(slot) != old:
                    raise RuntimeError("Restored name differs")
            except Exception:
                failures.append(f"{slot:02x}")
        check(lib.C_Logout(s))
        if failures:
            raise RuntimeError("Could not restore names in slots " + ", ".join(failures))
    print(
        "PASS F5 read/write/clear, duplicate rejection, F9 absence, short buffer and name restoration",
        flush=True,
    )


def verify_private_key(id, kind):
    login(1, os.environ["CNK_PIV_PIN"].encode())
    try:
        if kind in RSA_BITS:
            rsa_checks(id)
        elif kind == "p521":
            ecdsa_checks(id)
            derive(id)
        elif kind == "x25519":
            derive(id)
        else:
            eddsa_checks(id)
    finally:
        check(lib.C_Logout(s))


def generate_checks(id, kind):
    if not 1 <= id <= 24 or find(1, id):
        raise RuntimeError("Generation requires an explicit certificate-free PIV key slot")
    before = (
        public(id).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if find(2, id)
        else None
    )
    key_type, mechanism, params = {
        **{name: (0, 0, None) for name in RSA_BITS},
        "p521": (3, 0x1040, "06052b81040023"),
        "x25519": (0x41, 0x1056, "06032b656e"),
        "ed25519": (0x40, 0x1055, "06032b6570"),
    }[kind]
    common = [(0x100, key_type), (0x102, bytes([id])), (1, b"\1")]
    attributes = (
        [(0x121, RSA_BITS[kind]), (0x122, b"\1\0\1")]
        if kind in RSA_BITS
        else [(0x180, bytes.fromhex(params))]
    )
    pub, keep_pub = attrs([(0, 2)] + common + attributes)
    private, keep_private = attrs([(0, 3), (2, b"\1")] + common)
    mech = Mech(mechanism, None, 0)
    public_handle, private_handle = U(), U()
    login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
    try:
        check(
            lib.C_GenerateKeyPair(
                s,
                C.byref(mech),
                pub,
                len(pub),
                private,
                len(private),
                C.byref(public_handle),
                C.byref(private_handle),
            )
        )
    finally:
        check(lib.C_Logout(s))
    key = public(id)
    after = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if after == before:
        raise RuntimeError("Generation did not replace the selected public key")
    if (kind in RSA_BITS or kind == "p521") and key.key_size != RSA_BITS.get(kind, 521):
        raise RuntimeError("Generated key has the wrong size")
    verify_private_key(id, kind)
    print(
        f"PASS {kind} generation ID {id:02x}, fresh public key and independent private-operation verification",
        flush=True,
    )


def import_checks(id, kind):
    if not 1 <= id <= 24 or find(1, id):
        raise RuntimeError("Private-key import requires an explicit certificate-free PIV key slot")
    if kind in RSA_BITS:
        key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS[kind])
        numbers = key.private_numbers()
        integer = lambda v: v.to_bytes((v.bit_length() + 7) // 8, "big")
        values = [
            (0x100, 0),
            (0x120, integer(numbers.public_numbers.n)),
            (0x122, integer(numbers.public_numbers.e)),
        ]
        values += [
            (tag, integer(v))
            for tag, v in zip(
                range(0x124, 0x129), [numbers.p, numbers.q, numbers.dmp1, numbers.dmq1, numbers.iqmp]
            )
        ]
    elif kind == "p521":
        key = ec.generate_private_key(ec.SECP521R1())
        scalar = key.private_numbers().private_value
        # Exercise the PKCS#11 unsigned-integer convention, including omitted
        # leading zeros, instead of preparing a PIV fixed-width scalar here.
        values = [
            (0x100, 3),
            (0x180, bytes.fromhex("06052b81040023")),
            (0x11, scalar.to_bytes((scalar.bit_length() + 7) // 8, "big")),
        ]
    else:
        key = x25519.X25519PrivateKey.generate() if kind == "x25519" else ed25519.Ed25519PrivateKey.generate()
        values = [
            (0x100, 0x41 if kind == "x25519" else 0x40),
            (0x180, bytes.fromhex("06032b656e" if kind == "x25519" else "06032b6570")),
            (
                0x11,
                key.private_bytes(
                    serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
                ),
            ),
        ]
    template, keep = attrs([(0, 3), (0x102, bytes([id])), (1, b"\1"), (2, b"\1")] + values)
    handle = U()
    login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
    try:
        check(lib.C_CreateObject(s, template, len(template), C.byref(handle)))
    finally:
        check(lib.C_Logout(s))
    expected = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    actual = public(id).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if actual != expected:
        raise RuntimeError("Imported public key differs from the software-generated key")
    verify_private_key(id, kind)
    print(f"PASS {kind} import ID {id:02x}, exact public-key match and private operation", flush=True)


def main():
    initialized = False
    opened = False
    try:
        check(lib.C_Initialize(None))
        initialized = True
        count = U()
        check(lib.C_GetSlotList(1, None, C.byref(count)))
        slots = (U * count.value)()
        check(lib.C_GetSlotList(1, slots, C.byref(count)))
        if args.slot not in slots:
            raise RuntimeError("Requested slot is absent")
        info = TokenInfo()
        check(lib.C_GetTokenInfo(args.slot, C.byref(info)))
        actual_serial = bytes(info.serial).rstrip(b" \x00").decode("ascii")
        if actual_serial != args.serial:
            raise RuntimeError(f"Token serial mismatch: {actual_serial}")
        check(lib.C_OpenSession(args.slot, 6, None, None, C.byref(s)))
        opened = True
        if args.pin_managed_unconfigured:
            run_case("unconfigured PIN-managed login rollback", unconfigured_management_check)
        if args.name_slot:
            run_case("F5 name read/write/restore", lambda: names_checks(args.name_slot))
        for kind, id in generations:
            if id is not None:
                run_case(
                    f"{kind} key generation ID {id:02x}", lambda id=id, kind=kind: generate_checks(id, kind)
                )
        for kind, id in imports:
            if id is not None:
                run_case(
                    f"{kind} private-key import ID {id:02x}", lambda id=id, kind=kind: import_checks(id, kind)
                )
        if args.certificate_id is not None:
            run_case("certificate write/read/delete", certificate_checks)
            rv = lib.C_Logout(s)
            if rv not in (0, 257):
                check(rv)
        login(1, os.environ["CNK_PIV_PIN"].encode())
        for id in args.ecdsa_id:
            run_case(f"ECDSA ID {id:02x}", lambda id=id: ecdsa_checks(id))
        for id in args.eddsa_id:
            run_case(f"Ed25519 ID {id:02x}", lambda id=id: eddsa_checks(id))
        for id in args.derive_id:
            run_case(f"agreement ID {id:02x}", lambda id=id: derive(id))
        for id in args.rsa_id:
            run_case(f"RSA ID {id:02x}", lambda id=id: rsa_checks(id))
        if args.mldsa_id is not None:
            run_case("ML-DSA and ML-KEM", pqc_checks)
        run_case("hardware RNG 1024 bytes", random_check)
    finally:
        if opened:
            lib.C_Logout(s)
            check(lib.C_CloseSession(s))
        if initialized:
            check(lib.C_Finalize(None))
    report = {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "module": str(args.module),
        "module_sha256": hashlib.sha256(args.module.read_bytes()).hexdigest(),
        "slot": args.slot,
        "serial": args.serial,
        "checks": results,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    failed = sum((row["status"] == "fail" for row in results))
    print(f"{len(results) - failed}/{len(results)} requested hardware check groups passed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
