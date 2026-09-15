"""Explicit development-card PIN-managed fixture, with a tested recovery path.

Requires default PIN/PUK, an explicit reader/serial, an unconfigured card, and
the current management key. Prepare blocks the PUK; restore removes protection
data and uses libcanokey's authenticated retry reset to restore default PIN/PUK.
Prepare/restore preserve asymmetric keys and certificates. The separate clear-slot
mode explicitly deletes a selected Windows test key. Never logs credential/APDU bytes.
"""

import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path

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


class Attr(C.Structure):
    _pack_ = 1
    _fields_ = [("type", U), ("value", P), ("length", U)]


def bind(lib, signatures):
    for name, args in signatures.items():
        fn = getattr(lib, name)
        fn.argtypes, fn.restype = args, U


def check(status, operation):
    if status:
        raise RuntimeError(f"{operation}: 0x{status:08x}")


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


class Token:
    def __init__(self, path):
        os.environ["CNK_LOG_LEVEL"] = "none"
        self.lib = C.CDLL(str(path.resolve()))
        bind(
            self.lib,
            {
                "C_Initialize": [P],
                "C_Finalize": [P],
                "C_GetSlotList": [B, P, P],
                "C_OpenSession": [U, U, P, P, P],
                "C_CloseSession": [U],
                "C_Login": [U, U, P, U],
                "C_Logout": [U],
                "C_CreateObject": [U, P, U, P],
                "C_CNK_GetPivData": [U, P, U, P, P],
                "C_CNK_LoginPinManaged": [U, P, U],
                "C_CNK_FinalizePinManaged": [U, P, U],
                "C_CNK_UnblockPIN": [U, P, U, P, U, P],
            },
        )
        self.session = U()
        check(self.lib.C_Initialize(None), "initialize")
        try:
            count = U()
            check(self.lib.C_GetSlotList(1, None, C.byref(count)), "slot count")
            slots = (U * count.value)()
            check(self.lib.C_GetSlotList(1, slots, C.byref(count)), "slots")
            if list(slots) != [0]:
                raise RuntimeError("Expected one CanoKey slot")
            check(self.lib.C_OpenSession(0, 6, None, None, C.byref(self.session)), "open session")
        except BaseException:
            self.lib.C_Finalize(None)
            raise

    def close(self):
        self.lib.C_Logout(self.session)
        check(self.lib.C_CloseSession(self.session), "close session")
        check(self.lib.C_Finalize(None), "finalize")

    def login(self, role, secret):
        self.lib.C_Logout(self.session)
        check(self.lib.C_Login(self.session, role, secret, len(secret)), "login")

    def data(self, tag):
        data, size = (B * 1024)(), U(1024)
        check(self.lib.C_CNK_GetPivData(self.session, tag, len(tag), data, C.byref(size)), "read data")
        return bytes(data[: size.value])

    def write(self, tag, data):
        if tag != bytes.fromhex("5fc109"):
            raise RuntimeError("Only PRINTED has a data-object mapping in this fixture")
        oid = bytes.fromhex("60864801650307023001")
        values = [U(0), C.create_string_buffer(oid), C.create_string_buffer(data)]
        template = (Attr * 3)(
            *[
                Attr(t, C.cast(C.pointer(v), P), n)
                for t, v, n in zip((0, 0x12, 0x11), values, (4, len(oid), len(data)))
            ]
        )
        handle = U()
        try:
            check(self.lib.C_CreateObject(self.session, template, 3, C.byref(handle)), "write data")
        finally:
            C.memset(values[-1], 0, C.sizeof(values[-1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("prepare", "restore", "check-reset", "clear-slot", "malformed-policy")
    )
    parser.add_argument("--slot", type=lambda value: int(value, 16), choices=(0x9D, 0x9E, 0x83))
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--libcanokey", type=Path, required=True)
    parser.add_argument("--reader", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.mode == "clear-slot" and args.slot is None:
        parser.error("clear-slot requires an explicit Windows test slot (9D, 9E or 83)")
    if os.environ.get("CNK_PIV_PIN") != "123456" or os.environ.get("CNK_PIV_PUK") != "12345678":
        parser.error("This fixture requires explicitly supplied default development PIN/PUK")
    key = bytes.fromhex(os.environ["CNK_PIV_MANAGEMENT_KEY"])
    if len(key) != 24:
        parser.error("Management key must contain 24 bytes")
    admin, printed = bytes.fromhex("5fff00"), bytes.fromhex("5fc109")
    card = Card(args, key)
    try:
        if args.mode == "check-reset":
            card.reset_credentials()
        elif args.mode == "clear-slot":
            card.run("cnk_piv_delete_key_new", card.profile, args.slot, C.byref(card.access), None)
        else:
            token = Token(args.module)
            try:
                if args.mode == "prepare":
                    token.login(1, b"123456")
                    if token.data(admin) != b"\x53\0" or token.data(printed) != b"\x53\0":
                        raise RuntimeError("Prepare requires empty protection objects")
                    if card.metadata(0x81).remaining != 3:
                        raise RuntimeError("Prepare requires an unblocked PUK with three remaining tries")
                    token.login(0, key)
                    token.write(printed, bytes.fromhex("531c881a8918") + key)
                    card.write_admin(bytes.fromhex("8003810103"))
                    token.lib.C_Logout(token.session)
                    check(
                        token.lib.C_CNK_FinalizePinManaged(token.session, b"123456", 6), "finalize protection"
                    )
                    check(token.lib.C_CNK_LoginPinManaged(token.session, b"123456", 6), "protected login")
                    status = token.lib.C_CNK_UnblockPIN(token.session, b"12345678", 8, b"123456", 6, None)
                    if status != 0x1B:  # CKR_ACTION_PROHIBITED
                        raise RuntimeError(f"Protected recovery was not prohibited: {status:x}")
                    if card.metadata(0x81).remaining != 0:
                        raise RuntimeError("PUK was not blocked")
                elif args.mode == "malformed-policy":
                    token.login(1, b"123456")
                    if token.data(admin) != b"\x53\0":
                        raise RuntimeError("Malformed-policy test requires empty ADMIN DATA")
                    before = card.metadata(0x81).remaining
                    try:
                        for fields in (
                            bytes.fromhex("8200"),
                            bytes.fromhex("8300"),
                            bytes.fromhex("82008300"),
                        ):
                            card.write_admin(bytes([0x80, len(fields)]) + fields)
                            tries = B(0xDD)
                            status = token.lib.C_CNK_UnblockPIN(
                                token.session, b"12345678", 8, b"123456", 6, C.byref(tries)
                            )
                            if (
                                status != 0x30
                                or tries.value != 0xDD
                                or card.metadata(0x81).remaining != before
                            ):
                                raise RuntimeError(
                                    "Malformed policy did not fail closed before credential mutation"
                                )
                    finally:
                        card.write_admin(b"")
                    if token.data(admin) != b"\x53\0":
                        raise RuntimeError("Original ADMIN DATA was not restored")
                else:
                    token.login(0, key)
                    card.write_admin(b"")
                    token.write(printed, b"\x53\0")
            finally:
                token.close()
            if args.mode == "restore":
                card.reset_credentials()
        report = {
            "mode": args.mode,
            "serial": args.serial,
            "module_sha256": hashlib.sha256(args.module.read_bytes()).hexdigest(),
            "libcanokey_sha256": hashlib.sha256(args.libcanokey.read_bytes()).hexdigest(),
            "puk_remaining": card.metadata(0x81).remaining,
            "status": "pass",
        }
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"PASS {args.mode}; PUK remaining={report['puk_remaining']}")
    finally:
        card.close()


if __name__ == "__main__":
    main()
