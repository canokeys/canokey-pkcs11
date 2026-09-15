"""Shared PKCS#11 binding and session ownership for real-card tests."""

import ctypes as C
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519, mldsa, mlkem

U, B, P = C.c_ulong, C.c_ubyte, C.c_void_p


class Attr(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("type", U), ("value", P), ("len", U)]


class Mech(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("type", U), ("param", P), ("len", U)]


class ECDH(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("kdf", U), ("shared_len", U), ("shared", P), ("public_len", U), ("public", P)]


class OAEP(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("hash", U), ("mgf", U), ("source", U), ("len_ptr", P), ("len", U)]


class PSS(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("hash", U), ("mgf", U), ("salt", U)]


class Version(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("major", B), ("minor", B)]


class SessionInfo(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
    _fields_ = [("slot", U), ("state", U), ("flags", U), ("device_error", U)]


class TokenInfo(C.Structure):
    _pack_ = 1 if os.name == "nt" else 0
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


SIGNATURES = {
    "C_GetMechanismList": [U, P, C.POINTER(U)],
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
    "C_CNK_SetPIN": [U, B, P, U, P, U, P],
    "C_CNK_UnblockPIN": [U, P, U, P, U, P],
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
    "C_CNK_GetPivData": [U, P, U, P, C.POINTER(U)],
    "C_CNK_FinalizePinManaged": [U, P, U],
}


def check(rv, operation="PKCS11"):
    if rv:
        raise RuntimeError(f"{operation}: 0x{rv:x}")


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


class Token:
    def __init__(self, module, slot, serial):
        os.environ["CNK_UNSAFE_LOG_APDU"] = "0"
        self.lib = C.CDLL(str(module))
        self.session = U()
        self.initialized = False
        for name, types in SIGNATURES.items():
            function = getattr(self.lib, name)
            function.argtypes, function.restype = types, U
        try:
            check(self.lib.C_Initialize(None))
            self.initialized = True
            count = U()
            check(self.lib.C_GetSlotList(1, None, C.byref(count)))
            slots = (U * count.value)()
            check(self.lib.C_GetSlotList(1, slots, C.byref(count)))
            if slot not in slots:
                raise RuntimeError("Requested slot is absent")
            info = TokenInfo()
            check(self.lib.C_GetTokenInfo(slot, C.byref(info)))
            if bytes(info.serial).rstrip(b" \0").decode("ascii") != serial:
                raise RuntimeError("Token serial mismatch")
            check(self.lib.C_OpenSession(slot, 6, None, None, C.byref(self.session)))
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()

    def close(self):
        errors = []
        if self.session.value:
            rv = self.lib.C_Logout(self.session)
            if rv not in (0, 0x101):
                errors.append(rv)
            rv = self.lib.C_CloseSession(self.session)
            if rv:
                errors.append(rv)
            self.session.value = 0
        if self.initialized:
            rv = self.lib.C_Finalize(None)
            self.initialized = False
            if rv:
                errors.append(rv)
        if errors:
            raise RuntimeError(f"Session cleanup failed: {errors}")

    def switch_login(self, role, secret):
        rv = self.lib.C_Logout(self.session)
        if rv not in (0, 0x101):
            check(rv)
        self.login(role, secret)

    def data(self, tag):
        out, length = (B * 8192)(), U(8192)
        check(self.lib.C_CNK_GetPivData(self.session, tag, len(tag), out, C.byref(length)))
        return bytes(out[: length.value])

    def write_printed(self, data):
        template, storage = attrs([(0, 0), (0x12, bytes.fromhex("60864801650307023001")), (0x11, data)])
        handle = U()
        try:
            check(self.lib.C_CreateObject(self.session, template, len(template), C.byref(handle)))
        finally:
            C.memset(storage[-1], 0, C.sizeof(storage[-1]))

    def attr(self, key, t):
        a = Attr(t, None, 0)
        check(self.lib.C_GetAttributeValue(self.session, key, C.byref(a), 1))
        if a.len > 8192:
            raise RuntimeError("Attribute exceeds hardware-test buffer limit")
        b = C.create_string_buffer(a.len)
        a.value = C.cast(b, P)
        check(self.lib.C_GetAttributeValue(self.session, key, C.byref(a), 1))
        return b.raw[: a.len]

    def find(self, cls, id):
        a, keep = attrs([(0, cls), (258, bytes([id]))])
        check(self.lib.C_FindObjectsInit(self.session, a, len(a)))
        try:
            result = (U * 4)()
            n = U()
            check(self.lib.C_FindObjects(self.session, result, 4, C.byref(n)))
            return list(result[: n.value])
        finally:
            check(self.lib.C_FindObjectsFinal(self.session))

    def key_for(self, cls, id):
        keys = self.find(cls, id)
        if len(keys) != 1:
            raise RuntimeError(f"Expected exactly one class {cls} key with ID {id:02x}; found {len(keys)}")
        return keys[0]

    def public(self, id):
        key = self.key_for(2, id)
        kind = int.from_bytes(self.attr(key, 256), "little")
        if kind == 0:
            return rsa.RSAPublicNumbers(
                int.from_bytes(self.attr(key, 290), "big"), int.from_bytes(self.attr(key, 288), "big")
            ).public_key()
        if kind == 3:
            params = self.attr(key, 384)
            curve = {
                bytes.fromhex("06082a8648ce3d030107"): ec.SECP256R1,
                bytes.fromhex("06052b81040022"): ec.SECP384R1,
                bytes.fromhex("06052b81040023"): ec.SECP521R1,
                bytes.fromhex("06052b8104000a"): ec.SECP256K1,
            }[params]()
            point = self.attr(key, 385)
            start = 2 if point[1] < 128 else 2 + (point[1] & 127)
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, point[start:])
        if kind == 64:
            return ed25519.Ed25519PublicKey.from_public_bytes(self.attr(key, 385))
        if kind == 65:
            return x25519.X25519PublicKey.from_public_bytes(self.attr(key, 385))
        if kind == 0x4A:
            return mldsa.MLDSA65PublicKey.from_public_bytes(self.attr(key, 17))
        if kind == 0x49:
            return mlkem.MLKEM768PublicKey.from_public_bytes(self.attr(key, 17))
        raise RuntimeError(f"unsupported kind {kind}")

    def login(self, role, key):
        check(self.lib.C_Login(self.session, role, key, len(key)))

    def sign(self, id, mechanism, data):
        key = self.key_for(3, id)
        check(self.lib.C_SignInit(self.session, C.byref(mechanism), key))
        n = U()
        check(self.lib.C_Sign(self.session, data, len(data), None, C.byref(n)))
        out = C.create_string_buffer(n.value)
        short = U(1)
        if not self.lib.C_Sign(self.session, data, len(data), out, C.byref(short)) == 336:
            raise AssertionError("Hardware check failed")
        if not short.value == n.value:
            raise AssertionError("Hardware check failed")
        check(self.lib.C_Sign(self.session, data, len(data), out, C.byref(n)))
        return out.raw[: n.value]

    def verify(self, id, mechanism, data, signature):
        key = self.key_for(2, id)
        check(self.lib.C_VerifyInit(self.session, C.byref(mechanism), key))
        check(self.lib.C_Verify(self.session, data, len(data), signature, len(signature)))
        corrupted = bytes([signature[0] ^ 1]) + signature[1:]
        check(self.lib.C_VerifyInit(self.session, C.byref(mechanism), key))
        if self.lib.C_Verify(self.session, data, len(data), corrupted, len(corrupted)) != 0xC0:
            raise AssertionError("Host verification accepted a corrupted signature")
