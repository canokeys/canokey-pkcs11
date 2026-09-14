"""Windows real-card PKCS#11 checks using cryptography for independent verification.

Requires cryptography with ML-DSA/ML-KEM support, CNK_PIV_PIN, and explicit
slot/serial/key selections. SM2 provisioning also requires an OpenSSL CLI.
Certificate testing is opt-in and requires CNK_PIV_MANAGEMENT_KEY. It refuses
an existing certificate, deletes its test certificate, and checks key retention.
Explicit --replace-import-* / --replace-generate-* options overwrite a selected
certificate-free test slot and verify its public key and private operations.
Opaque PKCS#11 structures use Windows packing; template storage stays alive
through each borrowed C call. Credentials and shared secrets are never printed.
"""

from concurrent.futures import ThreadPoolExecutor
import threading
import subprocess
import tempfile
import time
import base64
import re
import shutil
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
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils, x25519, ed25519, mldsa, mlkem

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
PQC_KINDS = {
    "mldsa65": (0x4A, 0x1C, mldsa.MLDSA65PrivateKey),
    "mlkem768": (0x49, 0x0F, mlkem.MLKEM768PrivateKey),
}
EC_CURVES = {
    "p256": ("06082a8648ce3d030107", ec.SECP256R1),
    "p384": ("06052b81040022", ec.SECP384R1),
    "k256": ("06052b8104000a", ec.SECP256K1),
    "p521": ("06052b81040023", ec.SECP521R1),
}
KEY_KINDS = [*PQC_KINDS, *RSA_BITS, *EC_CURVES, "x25519", "ed25519"]
POLICY_KINDS = KEY_KINDS

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
parser.add_argument(
    "--pin-roundtrip-id",
    type=lambda x: int(x, 16),
    help="Temporarily change PIN to CNK_PIV_TEST_PIN, verify this EC key, then restore PIN",
)
parser.add_argument(
    "--concurrent-id",
    type=lambda x: int(x, 16),
    help="Sign with this EC key while another session reads token RNG",
)
parser.add_argument("--public-key-id", type=lambda x: int(x, 16), action="append", default=[])
parser.add_argument(
    "--external-write-id",
    type=lambda x: int(x, 16),
    help="Replace this certificate-free test slot from a child process and verify reset invalidation",
)
parser.add_argument(
    "--reset-script", type=Path, help="Explicit PowerShell USB-reset helper for the external-write test"
)
for kind in POLICY_KINDS:
    parser.add_argument(
        "--policy-" + kind + "-id",
        type=lambda x: int(x, 16),
        help="Replace this certificate-free test slot to exercise all PIN policies",
    )
parser.add_argument(
    "--sm2-provision-id",
    type=lambda x: int(x, 16),
    help="Replace a certificate-free EC test slot to validate SM2 generation/import; leave a P-521 fixture",
)
parser.add_argument("--openssl", type=Path, help="OpenSSL CLI for independent SM2 validation")
parser.add_argument("--report", type=Path)
args = parser.parse_args()
if (args.external_write_id is None) != (args.reset_script is None):
    parser.error("--external-write-id and --reset-script must be used together")
if args.external_write_id is not None:
    if "CNK_PIV_MANAGEMENT_KEY" not in os.environ:
        parser.error("CNK_PIV_MANAGEMENT_KEY is required for the external writer")
    os.environ["CNK_PIV_METADATA_CACHE"] = "1"
if os.name != "nt":
    parser.error("This ctypes layout targets native Windows only")
if "CNK_PIV_PIN" not in os.environ:
    parser.error("CNK_PIV_PIN is required")
policies = [(kind, getattr(args, "policy_" + kind + "_id")) for kind in POLICY_KINDS]
imports = [(kind, getattr(args, "replace_import_" + kind + "_id")) for kind in KEY_KINDS]
generations = [(kind, getattr(args, "replace_generate_" + kind + "_id")) for kind in KEY_KINDS]
if (
    args.certificate_id is not None
    or args.name_slot
    or args.sm2_provision_id is not None
    or any(id is not None for _, id in imports + generations + policies)
) and "CNK_PIV_MANAGEMENT_KEY" not in os.environ:
    parser.error("Card write tests require CNK_PIV_MANAGEMENT_KEY")
if args.pin_roundtrip_id is not None and "CNK_PIV_TEST_PIN" not in os.environ:
    parser.error("PIN roundtrip requires CNK_PIV_TEST_PIN")
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
    "C_WaitForSlotEvent": [U, C.POINTER(U), P],
    "C_CreateObject": [U, C.POINTER(Attr), U, C.POINTER(U)],
    "C_Initialize": [P],
    "C_Finalize": [P],
    "C_OpenSession": [U, U, P, P, C.POINTER(U)],
    "C_CloseSession": [U],
    "C_SessionCancel": [U, U],
    "C_CNK_LoginPinManaged": [U, P, U],
    "C_Login": [U, U, P, U],
    "C_Logout": [U],
    "C_SetPIN": [U, P, U, P, U],
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
    "C_SignUpdate": [U, P, U],
    "C_SignFinal": [U, P, C.POINTER(U)],
    "C_EncryptInit": [U, C.POINTER(Mech), U],
    "C_Encrypt": [U, P, U, P, C.POINTER(U)],
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
            bytes.fromhex("06052b8104000a"): ec.SECP256K1,
        }[params]()
        point = attr(key, 385)
        start = 2 if point[1] < 128 else 2 + (point[1] & 127)
        return ec.EllipticCurvePublicKey.from_encoded_point(curve, point[start:])
    if kind == 64:
        return ed25519.Ed25519PublicKey.from_public_bytes(attr(key, 385))
    if kind == 65:
        return x25519.X25519PublicKey.from_public_bytes(attr(key, 385))
    if kind == 0x4A:
        return mldsa.MLDSA65PublicKey.from_public_bytes(attr(key, 17))
    if kind == 0x49:
        return mlkem.MLKEM768PublicKey.from_public_bytes(attr(key, 17))
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


def verify(id, mechanism, data, signature):
    key = key_for(2, id)
    check(lib.C_VerifyInit(s, C.byref(mechanism), key))
    check(lib.C_Verify(s, data, len(data), signature, len(signature)))
    corrupted = bytes([signature[0] ^ 1]) + signature[1:]
    check(lib.C_VerifyInit(s, C.byref(mechanism), key))
    if lib.C_Verify(s, data, len(data), corrupted, len(corrupted)) != 0xC0:
        raise AssertionError("Host verification accepted a corrupted signature")


def derive(id, private_secret=True, expected_error=None):
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
        [
            (0, 4),
            (256, 16),
            (353, len(expected)),
            (1, b"\x00"),
            (2, bytes([private_secret])),
            (259, b"\x00"),
            (354, b"\x01"),
        ]
    )
    h = U()
    rv = lib.C_DeriveKey(s, C.byref(m), key_for(3, id), a, len(a), C.byref(h))
    if expected_error is not None:
        if rv != expected_error or h.value != 0:
            raise AssertionError("One-shot PIN-always derive did not fail closed")
        return
    check(rv)
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
        verify(id, m, msg, sig)
        print("PASS RSA SHA256", "PSS" if pss else "PKCS1", flush=True)
    # Independently check the host RSA public operation and its retry boundary.
    m = Mech(3, None, 0)  # CKM_RSA_X_509
    check(lib.C_EncryptInit(s, C.byref(m), key_for(2, id)))
    n = U()
    check(lib.C_Encrypt(s, msg, len(msg), None, C.byref(n)))
    out = C.create_string_buffer(n.value)
    short = U(1)
    if lib.C_Encrypt(s, msg, len(msg), out, C.byref(short)) != 0x150 or short.value != n.value:
        raise AssertionError("RSA encryption short-buffer retry failed")
    check(lib.C_Encrypt(s, msg, len(msg), out, C.byref(n)))
    numbers = pub.public_numbers()
    expected = pow(int.from_bytes(msg, "big"), numbers.e, numbers.n).to_bytes(pub.key_size // 8, "big")
    if out.raw[: n.value] != expected:
        raise AssertionError("Host RSA encryption differs from independent modular exponentiation")
    print("PASS RSA host encrypt and host verify/corrupted-signature rejection", flush=True)
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


def mldsa_checks(id):
    message = b"CanoKey independent ML-DSA verification"
    mechanism = Mech(29, None, 0)
    signature = sign(id, mechanism, message)
    public(id).verify(signature, message)
    verify(id, mechanism, message, signature)
    if len(signature) != 3309:
        raise AssertionError("Wrong ML-DSA signature length")
    print("PASS ML-DSA-65 hardware sign / independent OpenSSL and PKCS11 verify", flush=True)


def mlkem_checks(id, private_key=None, expected_error=None):
    mechanism = Mech(23, None, 0)
    attributes, keep = attrs([(259, b"\x00"), (354, b"\x01"), (353, 32), (2, b"\x00")])
    expected, ciphertext = public(id).encapsulate()
    card = U()
    rv = lib.C_DecapsulateKey(
        s,
        C.byref(mechanism),
        key_for(3, id),
        attributes,
        len(attributes),
        ciphertext,
        len(ciphertext),
        C.byref(card),
    )
    if expected_error is not None:
        if rv != expected_error or card.value != 0:
            raise AssertionError("One-shot PIN-always decapsulation did not fail closed")
        return
    check(rv)
    try:
        if attr(card, 17) != expected:
            raise AssertionError("ML-KEM card secret differs from independent OpenSSL encapsulation")
    finally:
        check(lib.C_DestroyObject(s, card))
    output = C.create_string_buffer(1088)
    length, host, card = U(1088), U(), U()
    check(
        lib.C_EncapsulateKey(
            s,
            C.byref(mechanism),
            key_for(2, id),
            attributes,
            len(attributes),
            output,
            C.byref(length),
            C.byref(host),
        )
    )
    try:
        expected = attr(host, 17)
        if private_key is not None and private_key.decapsulate(output.raw[: length.value]) != expected:
            raise AssertionError("PKCS11 ML-KEM encapsulation differs from independent OpenSSL decapsulation")
        check(
            lib.C_DecapsulateKey(
                s,
                C.byref(mechanism),
                key_for(3, id),
                attributes,
                len(attributes),
                output,
                length,
                C.byref(card),
            )
        )
        if attr(card, 17) != expected:
            raise AssertionError("ML-KEM host/card secrets differ")
    finally:
        if card.value:
            check(lib.C_DestroyObject(s, card))
        check(lib.C_DestroyObject(s, host))
    print("PASS ML-KEM-768 independent OpenSSL and PKCS11/card shared secrets", flush=True)


def pqc_checks():
    mldsa_checks(args.mldsa_id)
    mlkem_checks(args.mlkem_id)


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
        verify(id, Mech(4161, None, 0), data, sig)
        print(f"PASS ECDSA ID {id:02x}, {pub.key_size} bits, {algorithm.name}", flush=True)


def eddsa_checks(id):
    message = b"CanoKey Ed25519 hardware verification"
    signature = sign(id, Mech(0x1057, None, 0), message)
    public(id).verify(signature, message)
    print(f"PASS Ed25519 ID {id:02x}, independent software verification", flush=True)


def concurrency_check(id):
    pub = public(id)
    key = key_for(3, id)
    other = U()
    check(lib.C_OpenSession(args.slot, 6, None, None, C.byref(other)))
    try:
        with ThreadPoolExecutor(max_workers=2) as workers:
            for iteration in range(5):
                ready = threading.Barrier(2)
                digest = hashlib.sha256(f"CanoKey concurrent operation {iteration}".encode()).digest()

                def sign_other():
                    mechanism = Mech(4161, None, 0)
                    check(lib.C_SignInit(other, C.byref(mechanism), key))
                    output = C.create_string_buffer(132)
                    length = U(len(output))
                    ready.wait(timeout=10)
                    check(lib.C_Sign(other, digest, len(digest), output, C.byref(length)))
                    width = (pub.key_size + 7) // 8
                    if length.value != width * 2:
                        raise AssertionError("Concurrent signature has the wrong size")
                    signature = utils.encode_dss_signature(
                        int.from_bytes(output.raw[:width], "big"),
                        int.from_bytes(output.raw[width : 2 * width], "big"),
                    )
                    pub.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))

                def read_random():
                    output = C.create_string_buffer(32)
                    ready.wait(timeout=10)
                    check(lib.C_GenerateRandom(s, output, len(output)))
                    if len(set(output.raw)) < 8:
                        raise AssertionError("Concurrent RNG returned degenerate output")

                signed = workers.submit(sign_other)
                random = workers.submit(read_random)
                signed.result()
                random.result()
        for session in (s, other):
            info = SessionInfo()
            check(lib.C_GetSessionInfo(session, C.byref(info)))
            if info.state != 3:
                raise AssertionError("Concurrent operations changed the shared USER login")
    finally:
        lib.C_SessionCancel(other, 0x800)
        check(lib.C_CloseSession(other))
    print(
        "PASS two-session concurrent ECDSA/RNG, independent signature verification and shared USER state",
        flush=True,
    )


def public_fingerprint(id):
    encoded = public(id).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(encoded).hexdigest()


def external_reset_check(id):
    if not 1 <= id <= 24 or find(1, id):
        raise RuntimeError("External replacement requires an explicit certificate-free test slot")
    # Arm the reader watcher and discard initial insertion notifications.
    slot = U()
    for _ in range(16):
        rv = lib.C_WaitForSlotEvent(1, C.byref(slot), None)
        if rv == 8:
            break
        check(rv)
    else:
        raise RuntimeError("Initial reader events did not settle")
    before = public_fingerprint(id)
    with tempfile.TemporaryDirectory(prefix="cnk-external-write-") as directory:
        report_path = Path(directory) / "child.json"
        child = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--module",
                str(args.module),
                "--slot",
                str(args.slot),
                "--serial",
                args.serial,
                "--replace-generate-rsa-id",
                f"{id:02x}",
                "--public-key-id",
                f"{id:02x}",
                "--report",
                str(report_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if child.returncode:
            raise RuntimeError("External writer failed: " + child.stdout[-2000:])
        child_report = json.loads(report_path.read_text(encoding="utf-8"))
        expected = child_report["public_key_sha256"][f"{id:02x}"]
        if expected == before:
            raise AssertionError("External generation did not replace the test key")
        # A naturally expired TTL must not masquerade as successful event invalidation.
        if public_fingerprint(id) != before:
            raise RuntimeError("Parent cache expired before the reset; event-invalidation gate is unproven")
        # This helper only resets USB power. It must not install drivers or mutate keys.
        reset = subprocess.run(
            ["pwsh", "-NoProfile", "-File", str(args.reset_script.resolve())],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if reset.returncode:
            raise RuntimeError("USB reset failed: " + reset.stdout[-1000:])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            rv = lib.C_WaitForSlotEvent(1, C.byref(slot), None)
            if rv == 0 and slot.value == args.slot:
                break
            if rv not in (0, 8):
                check(rv)
            time.sleep(0.25)
        else:
            raise RuntimeError("No event for the selected CanoKey after reset")
        info = TokenInfo()
        check(lib.C_GetTokenInfo(args.slot, C.byref(info)))
        if bytes(info.serial).rstrip(b" \x00").decode("ascii") != args.serial:
            raise RuntimeError("Different token after reset")
        if public_fingerprint(id) != expected:
            raise AssertionError("Reader event did not invalidate the old public-key snapshot")
        rsa_checks(id)
    print(
        "PASS external key replacement, USB reinsert event, cache refresh and private operations in the existing session",
        flush=True,
    )
    return {
        "key_id": f"{id:02x}",
        "before_public_sha256": before,
        "after_public_sha256": expected,
        "event_slot": slot.value,
    }


def random_check():
    check(lib.C_GenerateRandom(s, None, 0))
    for length in [1, 256, 257, 1024, 65539]:
        output = C.create_string_buffer(length)
        check(lib.C_GenerateRandom(s, output, length))
        if length >= 1024 and len(set(output.raw)) <= 200:
            raise AssertionError("Degenerate hardware random output")
    print("PASS RNG lengths 0/1/256/257/1024/65539 and adapter chunk boundary", flush=True)


results = []


def run_case(name, operation):
    try:
        details = operation()
        row = {"name": name, "status": "pass"}
        if details is not None:
            row["details"] = details
        results.append(row)
    except Exception as error:
        detail = f"{type(error).__name__}: {error}"
        results.append({"name": name, "status": "fail", "detail": detail})
        print(f"FAIL {name}: {detail}", flush=True)


def pin_roundtrip(id):
    original = os.environ["CNK_PIV_PIN"].encode()
    temporary = os.environ["CNK_PIV_TEST_PIN"].encode()
    if not 6 <= len(temporary) <= 8 or temporary == original:
        raise RuntimeError("Temporary PIN must differ and contain 6 to 8 bytes")
    login(1, original)
    # Resolve the test key before attempting a credential mutation.
    public(id)
    attempted = False
    restored = False
    try:
        attempted = True
        check(lib.C_SetPIN(s, original, len(original), temporary, len(temporary)))
        # This uses the updated cached PIN, with no intervening login.
        ecdsa_checks(id)
        check(lib.C_Logout(s))
        login(1, temporary)
        check(lib.C_SetPIN(s, temporary, len(temporary), original, len(original)))
        restored = True
        check(lib.C_Logout(s))
        login(1, original)
        ecdsa_checks(id)
    finally:
        if attempted and not restored:
            rv = lib.C_SetPIN(s, temporary, len(temporary), original, len(original))
            # If the first change never committed, the temporary PIN is rejected.
            # Verify the known original instead; never loop over candidate PINs.
            if rv not in (0, 0xA0):
                check(rv)
            lib.C_Logout(s)
            login(1, original)
        rv = lib.C_Logout(s)
        if rv not in (0, 0x101):
            check(rv)
    print("PASS PIN change, cached-PIN signing, fresh login and original-PIN restoration", flush=True)


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


def verify_private_key(id, kind, private_key=None):
    login(1, os.environ["CNK_PIV_PIN"].encode())
    try:
        if kind in RSA_BITS:
            rsa_checks(id)
        elif kind == "mldsa65":
            mldsa_checks(id)
        elif kind == "mlkem768":
            mlkem_checks(id, private_key)
        elif kind in EC_CURVES:
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
        **{name: (value[0], value[1], None) for name, value in PQC_KINDS.items()},
        **{name: (3, 0x1040, value[0]) for name, value in EC_CURVES.items()},
        "x25519": (0x41, 0x1056, "06032b656e"),
        "ed25519": (0x40, 0x1055, "06032b6570"),
    }[kind]
    common = [(0x100, key_type), (0x102, bytes([id])), (1, b"\1")]
    attributes = (
        [(0x121, RSA_BITS[kind]), (0x122, b"\1\0\1")]
        if kind in RSA_BITS
        else [(0x61D, 2)] if kind in PQC_KINDS else [(0x180, bytes.fromhex(params))]
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
    if (kind in RSA_BITS or kind in EC_CURVES) and key.key_size != (
        RSA_BITS[kind] if kind in RSA_BITS else EC_CURVES[kind][1]().key_size
    ):
        raise RuntimeError("Generated key has the wrong size")
    verify_private_key(id, kind)
    print(
        f"PASS {kind} generation ID {id:02x}, fresh public key and independent private-operation verification",
        flush=True,
    )


def import_checks(id, kind, policy=2, exercise=True):
    if not 1 <= id <= 24 or find(1, id):
        raise RuntimeError("Private-key import requires an explicit certificate-free PIV key slot")
    if kind in PQC_KINDS:
        key_type, _, key_class = PQC_KINDS[kind]
        key = key_class.generate()
        values = [(0x100, key_type), (0x61D, 2), (0x637, key.private_bytes_raw())]
    elif kind in RSA_BITS:
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
    elif kind in EC_CURVES:
        key = ec.generate_private_key(EC_CURVES[kind][1]())
        scalar = key.private_numbers().private_value
        # Exercise the PKCS#11 unsigned-integer convention, including omitted
        # leading zeros, instead of preparing a PIV fixed-width scalar here.
        values = [
            (0x100, 3),
            (0x180, bytes.fromhex(EC_CURVES[kind][0])),
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
    template, keep = attrs(
        [
            (0, 3),
            (0x102, bytes([id])),
            (1, b"\1"),
            (2, bytes([policy != 1])),
            (0xC34E4B01, bytes([policy])),
            (0xC34E4B02, b"\1"),
        ]
        + values
    )
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
    if exercise:
        verify_private_key(id, kind, key)
        print(f"PASS {kind} import ID {id:02x}, exact public-key match and private operation", flush=True)
        return None
    return key


def logout_if_logged_in():
    rv = lib.C_Logout(s)
    if rv not in (0, 0x101):
        check(rv)


def policy_sign(id, kind, policy):
    pub = public(id)
    private = key_for(3, id)
    message = b"CanoKey PIN-always retry must sign this message exactly once"
    code = (
        64 if kind in RSA_BITS else 0x1044 if kind in EC_CURVES else {"ed25519": 0x1057, "mldsa65": 29}[kind]
    )
    mechanism = Mech(code, None, 0)

    def validate(signature):
        if kind in RSA_BITS:
            pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        elif kind in EC_CURVES:
            width = (pub.key_size + 7) // 8
            encoded = utils.encode_dss_signature(
                int.from_bytes(signature[:width], "big"), int.from_bytes(signature[width:], "big")
            )
            pub.verify(encoded, message, ec.ECDSA(hashes.SHA256()))
        else:
            pub.verify(signature, message)

    for multipart in (False, True):
        check(lib.C_SignInit(s, C.byref(mechanism), private))
        if multipart:
            if policy == 3:
                if lib.C_SignUpdate(s, message[:13], 13) != 0x101:
                    raise AssertionError("PIN-always Update accepted input before context login")
                login(2, os.environ["CNK_PIV_PIN"].encode())
            check(lib.C_SignUpdate(s, message[:13], 13))
            check(lib.C_SignUpdate(s, message[13:], len(message) - 13))

        def execute(output, length):
            return (
                lib.C_SignFinal(s, output, C.byref(length))
                if multipart
                else lib.C_Sign(s, message, len(message), output, C.byref(length))
            )

        length = U()
        check(execute(None, length))
        output = C.create_string_buffer(b"\xcc" * length.value)
        small = U(1)
        if execute(output, small) != 0x150 or small.value != length.value:
            raise AssertionError("Signing preflight lost its operation or output size")
        if policy == 3 and not multipart:
            if execute(output, length) != 0x101 or output.raw[: length.value] != b"\xcc" * length.value:
                raise AssertionError("PIN-always sign did not preserve its auth-required operation")
            login(2, os.environ["CNK_PIV_PIN"].encode())
        check(execute(output, length))
        validate(output.raw[: length.value])
        if execute(None, length) != 0x91:
            raise AssertionError("Successful signing did not consume its context")
    # Authentication/cancellation is operation-local, not reusable on a new Init.
    check(lib.C_SignInit(s, C.byref(mechanism), private))
    if policy == 3:
        output = C.create_string_buffer(4096)
        length = U(len(output))
        if lib.C_Sign(s, message, len(message), output, C.byref(length)) != 0x101:
            raise AssertionError("A previous context login authorized a new signature")
        login(2, os.environ["CNK_PIV_PIN"].encode())
    check(lib.C_SessionCancel(s, 0x800))
    if lib.C_Login(s, 2, os.environ["CNK_PIV_PIN"].encode(), len(os.environ["CNK_PIV_PIN"])) != 0x91:
        raise AssertionError("Cancelled signing retained context-specific authentication")


def policy_decrypt(id, policy):
    pub = public(id)
    private = key_for(3, id)
    message = b"PIN-policy decryption"
    for oaep in (False, True):
        pad = (
            padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None) if oaep else padding.PKCS1v15()
        )
        ciphertext = pub.encrypt(message, pad)
        parameters = OAEP(592, 2, 1, None, 0)
        mechanism = Mech(
            9 if oaep else 1,
            C.cast(C.pointer(parameters), P) if oaep else None,
            C.sizeof(parameters) if oaep else 0,
        )
        check(lib.C_DecryptInit(s, C.byref(mechanism), private))
        length = U()
        check(lib.C_Decrypt(s, ciphertext, len(ciphertext), None, C.byref(length)))
        output = C.create_string_buffer(length.value)
        if policy == 3:
            if lib.C_Decrypt(s, ciphertext, len(ciphertext), output, C.byref(length)) != 0x101:
                raise AssertionError("PIN-always decrypt did not require operation authentication")
            login(2, os.environ["CNK_PIV_PIN"].encode())
        check(lib.C_Decrypt(s, ciphertext, len(ciphertext), output, C.byref(length)))
        if output.raw[: length.value] != message:
            raise AssertionError("PIN-policy decrypt returned wrong plaintext")
        check(lib.C_DecryptInit(s, C.byref(mechanism), private))
        if policy == 3:
            length = U(len(output))
            if lib.C_Decrypt(s, ciphertext, len(ciphertext), output, C.byref(length)) != 0x101:
                raise AssertionError("Context-specific decrypt authentication was reused")
            login(2, os.environ["CNK_PIV_PIN"].encode())
        check(lib.C_SessionCancel(s, 0x200))


def policy_matrix(id, kind):
    if not 1 <= id <= 24 or find(1, id):
        raise RuntimeError("PIN-policy testing requires an explicit certificate-free test slot")
    try:
        for policy in (1, 2, 3):
            logout_if_logged_in()
            software = import_checks(id, kind, policy=policy, exercise=False)
            if attr(key_for(2, id), 0xC34E4B01) != bytes([policy]):
                raise AssertionError("Written PIN policy did not round-trip")
            visible = find(3, id)
            if bool(visible) != (policy == 1):
                raise AssertionError("Private-key visibility disagrees with the PIN policy")
            if policy != 1:
                login(1, os.environ["CNK_PIV_PIN"].encode())
            private_handle = key_for(3, id)
            if attr(private_handle, 2) != bytes([policy != 1]) or attr(private_handle, 0x202) != bytes(
                [policy == 3]
            ):
                raise AssertionError("PKCS11 private/always-authenticate attributes disagree with policy")
            if kind in PQC_KINDS:
                seed = Attr(0x637, None, 0)
                if lib.C_GetAttributeValue(s, private_handle, C.byref(seed), 1) != 0x11:
                    raise AssertionError("PQC seed is readable through the private-key object")
            if kind not in ("x25519", "mlkem768"):
                policy_sign(id, kind, policy)
            if kind in RSA_BITS:
                policy_decrypt(id, policy)
            elif kind in EC_CURVES or kind == "x25519":
                derive(id, private_secret=False, expected_error=0x101 if policy == 3 else None)
            elif kind == "mlkem768":
                mlkem_checks(id, software, expected_error=0x101 if policy == 3 else None)
            if policy == 3 and kind in ("x25519", "mlkem768"):
                if (
                    lib.C_Login(s, 2, os.environ["CNK_PIV_PIN"].encode(), len(os.environ["CNK_PIV_PIN"]))
                    != 0x91
                ):
                    raise AssertionError("One-shot operation exposed a context-login boundary")
            info = SessionInfo()
            check(lib.C_GetSessionInfo(s, C.byref(info)))
            if info.state != (2 if policy == 1 else 3):
                raise AssertionError("Key operations changed the token login role")
            print(
                f"PASS {kind} ID {id:02x} PIN policy {policy}, visibility, operations and cleanup", flush=True
            )
    finally:
        logout_if_logged_in()
        # These are explicitly replaceable fixtures, not the original card keys.
        # Leave a PIN-once key; PQC reuse of the RSA fixture ends with RSA again.
        import_checks(id, "rsa" if kind in PQC_KINDS else kind)


def sm2_provisioning(id):
    if not 1 <= id <= 24 or find(1, id):
        raise RuntimeError("SM2 provisioning requires an explicit certificate-free test slot")
    executable = (
        args.openssl
        or shutil.which("openssl")
        or Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
    )
    if not Path(executable).is_file():
        raise RuntimeError("Pass --openssl with a CLI supporting SM2")

    def openssl(*arguments, data=None):
        result = subprocess.run(
            [str(executable), *arguments],
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        if result.returncode:
            raise RuntimeError(
                "OpenSSL SM2 validation failed: " + result.stderr.decode(errors="replace")[-500:]
            )
        return result.stdout

    params = bytes.fromhex("06082a811ccf5501822d")

    def point():
        handle = key_for(2, id)
        if attr(handle, 0x180) != params:
            raise AssertionError("SM2 curve parameters differ")
        encoded = attr(handle, 0x181)
        if len(encoded) != 67 or encoded[:3] != b"\x04\x41\x04":
            raise AssertionError("SM2 public point is not an uncompressed PKCS11 OCTET STRING")
        return encoded[2:]

    # Validate software support and obtain an independent scalar/public pair before card writes.
    private_pem = openssl("genpkey", "-algorithm", "SM2")
    description = openssl("pkey", "-text", "-noout", data=private_pem).decode("ascii")
    scalar = bytes.fromhex(
        "".join(re.findall(r"[0-9a-fA-F]{2}", description.split("priv:")[1].split("pub:")[0]))
    )
    expected = bytes.fromhex(
        "".join(re.findall(r"[0-9a-fA-F]{2}", description.split("pub:")[1].split("ASN1 OID:")[0]))
    )
    if len(scalar) != 32 or len(expected) != 65 or "ASN1 OID: SM2" not in description:
        raise AssertionError("Unexpected OpenSSL SM2 key representation")
    common = [(0x100, 3), (0x102, bytes([id])), (1, b"\1")]
    try:
        login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
        try:
            pub, keep_pub = attrs([(0, 2), (0x180, params)] + common)
            private, keep_private = attrs([(0, 3), (2, b"\1")] + common)
            mechanism = Mech(0x1040, None, 0)
            a, b = U(), U()
            check(
                lib.C_GenerateKeyPair(
                    s, C.byref(mechanism), pub, len(pub), private, len(private), C.byref(a), C.byref(b)
                )
            )
        finally:
            logout_if_logged_in()
        generated = point()
        # Canonical id-ecPublicKey/SM2 SPKI framing; OpenSSL validates the generated point.
        der = bytes.fromhex("3059301306072a8648ce3d020106082a811ccf5501822d034200") + generated
        pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(der) + b"\n-----END PUBLIC KEY-----\n"
        openssl("pkey", "-pubin", "-pubcheck", "-noout", data=pem)
        template, keep = attrs([(0, 3), (2, b"\1"), (0x180, params), (0x11, scalar)] + common)
        login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
        try:
            handle = U()
            check(lib.C_CreateObject(s, template, len(template), C.byref(handle)))
        finally:
            logout_if_logged_in()
        if point() != expected or point() == generated:
            raise AssertionError("Imported SM2 point differs from independent scalar multiplication")
        login(1, os.environ["CNK_PIV_PIN"].encode())
        private = key_for(3, id)
        if attr(private, 0x108) != b"\0" or attr(private, 0x10C) != b"\0":
            raise AssertionError("SM2 advertised unsupported PKCS11 private operations")
        mechanism = Mech(0x1041, None, 0)
        if lib.C_SignInit(s, C.byref(mechanism), private) != 0x68:
            raise AssertionError("SM2 signing returned an unexpected status")
        peer = C.create_string_buffer(expected)
        parameters = ECDH(1, 0, None, len(expected), C.cast(peer, P))
        mechanism = Mech(4176, C.cast(C.pointer(parameters), P), C.sizeof(parameters))
        secret = U()
        if lib.C_DeriveKey(s, C.byref(mechanism), private, None, 0, C.byref(secret)) != 0x68 or secret.value:
            raise AssertionError("SM2 derive escaped its unsupported-operation boundary")
    finally:
        logout_if_logged_in()
        import_checks(id, "p521")
    print(
        "PASS SM2 generation/public-point validation, scalar import and PKCS11 operation bounds", flush=True
    )


def main():
    initialized = False
    opened = False
    fingerprints = {}
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
        if args.pin_roundtrip_id is not None:
            run_case("PIN change/cache/restore", lambda: pin_roundtrip(args.pin_roundtrip_id))
        if args.pin_managed_unconfigured:
            run_case("unconfigured PIN-managed login rollback", unconfigured_management_check)
        if args.name_slot:
            run_case("F5 name read/write/restore", lambda: names_checks(args.name_slot))
        for kind, id in policies:
            if id is not None:
                run_case(
                    f"{kind} PIN-policy matrix ID {id:02x}", lambda id=id, kind=kind: policy_matrix(id, kind)
                )
        if args.sm2_provision_id is not None:
            run_case(
                f"SM2 provisioning ID {args.sm2_provision_id:02x}",
                lambda: sm2_provisioning(args.sm2_provision_id),
            )
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
        if args.concurrent_id is not None:
            run_case("two-session concurrent ECDSA/RNG", lambda: concurrency_check(args.concurrent_id))
        run_case("hardware RNG length/chunk matrix", random_check)
        if args.external_write_id is not None:
            run_case(
                "external write/reset/cache refresh", lambda: external_reset_check(args.external_write_id)
            )
        fingerprints = {f"{id:02x}": public_fingerprint(id) for id in args.public_key_id}
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
        "public_key_sha256": fingerprints,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    failed = sum((row["status"] == "fail" for row in results))
    print(f"{len(results) - failed}/{len(results)} requested hardware check groups passed", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
