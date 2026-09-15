"""Explicit, restorable development-card fixtures; no automatic provisioning."""

import ctypes as C
import os
from pkcs11 import check, attrs

P, U, Z, B = C.c_void_p, C.c_uint32, C.c_size_t, C.c_ubyte


class Error(C.Structure):
    _fields_ = [(n, U) for n in ("size", "kind", "phase", "reference", "presence")]
    _fields_ += [("sw", C.c_uint16), ("tries", B), ("reserved", B)]


class Metadata(C.Structure):
    _fields_ = [("size", U), ("presence", U)]
    _fields_ += [
        (n, B) for n in ("algorithm", "pin", "touch", "origin", "default", "total", "remaining", "reserved")
    ]


class Management(C.Structure):
    _fields_ = [
        ("size", U),
        ("algorithm", U),
        ("mode", U),
        ("key", P),
        ("key_len", Z),
        ("challenge", P),
        ("challenge_len", Z),
    ]


class Access(C.Structure):
    _fields_ = [("size", U), ("pin", P), ("pin_len", Z), ("management", P)]


def bind(lib, signatures):
    for name, args in signatures.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, U


class Card:
    def __init__(self, args, key):
        self.lib = C.CDLL(str(args.libcanokey.resolve()))
        self.pcsc = C.WinDLL("winscard.dll")
        bind(
            self.pcsc,
            {
                "SCardEstablishContext": [U, P, P, P],
                "SCardReleaseContext": [Z],
                "SCardConnectW": [Z, C.c_wchar_p, U, U, P, P],
                "SCardDisconnect": [Z, U],
                "SCardBeginTransaction": [Z],
                "SCardEndTransaction": [Z, U],
                "SCardTransmit": [Z, P, P, U, P, P, P],
            },
        )
        bind(
            self.lib,
            {
                "cnk_probe_device_new": [U, P, P, P],
                "cnk_operation_start": [P, P, P],
                "cnk_operation_advance": [P, P, Z, P, P],
                "cnk_operation_command": [P, P, P],
                "cnk_operation_take_profile": [P, P],
                "cnk_operation_free": [P],
                "cnk_profile_free": [P],
                "cnk_profile_serial_u32": [P, P],
                "cnk_operation_metadata": [P, P],
                "cnk_piv_get_metadata_new": [P, U, P, P, P, P],
                "cnk_piv_reset_pin_puk_retries_new": [P, U, U, P, P, P, P],
                "cnk_piv_delete_key_new": [P, U, P, P, P, P],
                "cnk_piv_write_object_new": [P, P, Z, P, Z, P, P, P, P],
            },
        )
        self.context, self.card, self.profile = Z(), Z(), P()
        self.lib.cnk_operation_free.restype = None
        self.lib.cnk_profile_free.restype = None
        self.protocol = U()
        self.key, self.pin = C.create_string_buffer(key), C.create_string_buffer(b"123456")
        try:
            check(self.pcsc.SCardEstablishContext(2, None, None, C.byref(self.context)), "establish")
            check(
                self.pcsc.SCardConnectW(
                    self.context, args.reader, 2, 3, C.byref(self.card), C.byref(self.protocol)
                ),
                "connect",
            )
            self.run(
                "cnk_probe_device_new",
                1,
                None,
                result=lambda op: self.lib.cnk_operation_take_profile(op, C.byref(self.profile)),
            )
            serial = U()
            check(self.lib.cnk_profile_serial_u32(self.profile, C.byref(serial)), "serial")
            if str(serial.value) != args.serial:
                raise RuntimeError("Card serial mismatch")
            algorithm = self.metadata(0x9B).algorithm
            if algorithm not in (3, 0x0A):
                raise RuntimeError("Unsupported management-key algorithm")
            self.management = Management(
                C.sizeof(Management), 1 if algorithm == 3 else 2, 1, C.cast(self.key, P), len(key), None, 0
            )
            self.access = Access(
                C.sizeof(Access), C.cast(self.pin, P), 6, C.cast(C.pointer(self.management), P)
            )
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.profile:
            self.lib.cnk_profile_free(self.profile)
            self.profile = P()
        if self.card:
            self.pcsc.SCardDisconnect(self.card, 0)
            self.card = Z()
        if self.context:
            self.pcsc.SCardReleaseContext(self.context)
            self.context = Z()
        C.memset(self.key, 0, C.sizeof(self.key))
        C.memset(self.pin, 0, C.sizeof(self.pin))

    def run(self, factory, *inputs, result=None):
        op, error, step = P(), Error(), U()
        error.size = C.sizeof(error)
        check(self.pcsc.SCardBeginTransaction(self.card), "begin transaction")
        try:
            status = getattr(self.lib, factory)(*inputs, C.byref(op), C.byref(error))
            if not status:
                status = self.lib.cnk_operation_start(op, C.byref(step), C.byref(error))
            exchanges = 0
            while not status and step.value == 1:
                exchanges += 1
                if exchanges > 4096:
                    raise RuntimeError("Exchange limit")
                command, length = (B * 65544)(), Z(65544)
                check(self.lib.cnk_operation_command(op, command, C.byref(length)), "command")
                response, capacity = (B * 65538)(), U(65538)
                pci = (U * 2)(self.protocol.value, 8)
                try:
                    check(
                        self.pcsc.SCardTransmit(
                            self.card, pci, command, length.value, None, response, C.byref(capacity)
                        ),
                        "transmit",
                    )
                    status = self.lib.cnk_operation_advance(
                        op, response, capacity.value, C.byref(step), C.byref(error)
                    )
                finally:
                    C.memset(command, 0, C.sizeof(command))
                    C.memset(response, 0, C.sizeof(response))
            if status or step.value != 2:
                raise RuntimeError(
                    f"{factory}: status={status} kind={error.kind} phase={error.phase} SW={error.sw:04x}"
                )
            if result:
                check(result(op), "result")
        finally:
            if op:
                self.lib.cnk_operation_free(op)
            check(self.pcsc.SCardEndTransaction(self.card, 0), "end transaction")

    def metadata(self, reference):
        result = Metadata()
        result.size = C.sizeof(result)
        self.run(
            "cnk_piv_get_metadata_new",
            self.profile,
            reference,
            None,
            None,
            result=lambda op: self.lib.cnk_operation_metadata(op, C.byref(result)),
        )
        if reference in (0x80, 0x81) and not result.presence & 16:
            raise RuntimeError("Credential metadata has no retry counter")
        return result

    def reset_credentials(self):
        self.run("cnk_piv_reset_pin_puk_retries_new", self.profile, 3, 3, C.byref(self.access), None)
        for reference in (0x80, 0x81):
            metadata = self.metadata(reference)
            if metadata.remaining != 3 or metadata.total != 3 or not metadata.default:
                raise RuntimeError("Default credential restoration failed")

    def write_admin(self, value):
        self.run(
            "cnk_piv_write_object_new",
            self.profile,
            bytes.fromhex("5fff00"),
            3,
            value,
            len(value),
            C.byref(self.access),
            None,
        )


def certificate(token, id, directory):
    from asn1crypto import x509 as asn1_x509
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from datetime import datetime, timedelta, timezone
    import hashlib
    from pkcs11 import rsa, ec, Mech, U
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import utils

    rv = token.lib.C_Logout(token.session)
    if rv not in (0, 0x101):
        check(rv)
    pub = token.public(id)
    if not isinstance(pub, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        raise RuntimeError("Windows certificates require RSA or NIST EC keys")
    directory.mkdir(parents=True, exist_ok=True)
    existing = token.find(1, id)
    backup = directory / f"original-id-{id:02x}.der"
    if existing and not backup.exists():
        backup.write_bytes(token.attr(existing[0], 17))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"CanoKey Windows development ID {id:02x}")])
    now = datetime.now(timezone.utc)
    is_rsa = isinstance(pub, rsa.RSAPublicKey)
    placeholder = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if is_rsa
        else ec.generate_private_key(pub.curve)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, is_rsa, False, False, False, False, False, False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .sign(placeholder, hashes.SHA256())
    )
    token.login(1, os.environ["CNK_PIV_PIN"].encode())
    if is_rsa:
        signature = token.sign(id, Mech(0x40, None, 0), cert.tbs_certificate_bytes)
    else:
        raw = token.sign(id, Mech(0x1041, None, 0), hashlib.sha256(cert.tbs_certificate_bytes).digest())
        width = len(raw) // 2
        signature = utils.encode_dss_signature(
            int.from_bytes(raw[:width], "big"), int.from_bytes(raw[width:], "big")
        )
    encoded = asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    encoded["signature_value"] = signature
    der = encoded.dump()
    signed = x509.load_der_x509_certificate(der)
    signed.verify_directly_issued_by(signed)
    check(token.lib.C_Logout(token.session))
    token.login(0, bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"]))
    template, keep = attrs([(0, 1), (128, 0), (258, bytes([id])), (1, b"\1"), (17, der)])
    handle = U()
    check(token.lib.C_CreateObject(token.session, template, len(template), C.byref(handle)))
    if token.attr(handle, 17) != der:
        raise RuntimeError("Certificate readback differs from the signed DER")
    (directory / f"certificate-id-{id:02x}.der").write_bytes(der)
    thumbprint = signed.fingerprint(hashes.SHA1()).hex().upper()
    check(token.lib.C_Logout(token.session))
    print(f"PASS certificate ID {id:02x} signed by its card key; thumbprint={thumbprint}", flush=True)


def run(token, args):
    if args.action == "certificate":
        if args.output is None:
            raise ValueError("Certificate fixture requires --output for backups and DER")
        return certificate(token, args.id, args.output)
    if os.name != "nt" or not args.libcanokey or not args.reader:
        raise ValueError("This fixture requires Windows, --libcanokey and --reader")
    if os.environ.get("CNK_PIV_PIN") != "123456" or os.environ.get("CNK_PIV_PUK") != "12345678":
        raise ValueError("Explicit default development PIN/PUK are required for credential-reset fixtures")
    key = bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"])
    if len(key) != 24:
        raise ValueError("Management key must contain 24 bytes")
    card = Card(args, key)
    admin, printed = bytes.fromhex("5fff00"), bytes.fromhex("5fc109")
    try:
        if args.action == "check-reset":
            card.reset_credentials()
        elif args.action == "clear-slot":
            slot = [0x9A, 0x9C, 0x9D, 0x9E, *range(0x82, 0x96)][args.id - 1]
            card.run("cnk_piv_delete_key_new", card.profile, slot, C.byref(card.access), None)
        elif args.action == "prepare":
            token.switch_login(1, b"123456")
            if (
                token.data(admin) != b"\x53\0"
                or token.data(printed) != b"\x53\0"
                or card.metadata(0x81).remaining != 3
            ):
                raise ValueError("Prepare requires empty protection objects and three PUK tries")
            token.switch_login(0, key)
            token.write_printed(bytes.fromhex("531c881a8918") + key)
            card.write_admin(bytes.fromhex("8003810103"))
            check(token.lib.C_Logout(token.session))
            check(token.lib.C_CNK_FinalizePinManaged(token.session, b"123456", 6))
            check(token.lib.C_CNK_LoginPinManaged(token.session, b"123456", 6))
            if (
                token.lib.C_CNK_UnblockPIN(token.session, b"12345678", 8, b"123456", 6, None) != 0x1B
                or card.metadata(0x81).remaining != 0
            ):
                raise AssertionError("PIN-managed recovery was not disabled")
        elif args.action == "malformed-policy":
            token.switch_login(1, b"123456")
            if token.data(admin) != b"\x53\0":
                raise ValueError("Malformed-policy test requires empty ADMIN DATA")
            before = card.metadata(0x81).remaining
            try:
                for fields in (bytes.fromhex("8200"), bytes.fromhex("8300"), bytes.fromhex("82008300")):
                    card.write_admin(bytes([0x80, len(fields)]) + fields)
                    tries = B(0xDD)
                    rv = token.lib.C_CNK_UnblockPIN(
                        token.session, b"12345678", 8, b"123456", 6, C.byref(tries)
                    )
                    if rv != 0x30 or tries.value != 0xDD or card.metadata(0x81).remaining != before:
                        raise AssertionError("Malformed policy did not fail before credential mutation")
            finally:
                card.write_admin(b"")
        elif args.action == "restore":
            token.switch_login(0, key)
            card.write_admin(b"")
            token.write_printed(b"\x53\0")
            check(token.lib.C_Logout(token.session))
            card.reset_credentials()
        else:
            raise ValueError("Unknown fixture action")
        print(f"PASS fixture {args.action}; PUK remaining={card.metadata(0x81).remaining}")
    finally:
        card.close()
