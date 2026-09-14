# F5 PIV container names

`C_CNK_GetContainerName` and `C_CNK_SetContainerName` use physical PIV
references: 9A/9C/9D/9E, 82..95 and F9. They do not expand Cryptoki object
enumeration or change CKA_LABEL/CKA_MODIFIABLE. Names are raw UTF-16LE, up to
78 bytes, without NUL or unpaired surrogates. NULL/zero Set clears the name.

Reads are unauthenticated and fresh, including NULL-buffer size queries.
Writes require an RW session and SO or protected-management authorization.
The management reservation spans SELECT, authentication and one short F5
command. There is no reselect between authentication and the mutation.

The shared PIV RNG version gate reads GET VERSION in the selected transaction.
PIV before 6.0.0 (or unavailable GET VERSION, as for RNG) returns
CKR_FUNCTION_NOT_SUPPORTED without sending F5. PIV 6.0.0 and later support F5;
unexpected 6D00/6A81 from F5 become DEVICE_ERROR, not legacy fallback.
No negative capability cache is used. Version transport/parse failures propagate.
6A88 becomes CKR_KEY_HANDLE_INVALID, 6982 USER_NOT_LOGGED_IN, 6A80 DATA_INVALID,
6A86 ARGUMENTS_BAD, 6700 DATA_LEN_RANGE; 6900 and unexpected status/transport
errors become DEVICE_ERROR. Malformed successful reads become DATA_INVALID.
Size errors do not partially copy output. SET never retries; a lost response
can follow a committed name. Public snapshots invalidate before transmission.

Firmware owns uniqueness, key replacement, reset and move semantics. The host
does not emulate these by deleting keys, changing credentials or ADMIN DATA.

Configure CNK_BUILD_CONTAINER_NAME_TESTS=ON for isolated API/transport tests.
They link production extension code with fake lifecycle/session/transport
seams; they cover status fallback, short APDU encoding, UTF-16, all slot values,
buffer semantics, authorization failures and reservation/reference cleanup.
They do not replace full concurrency/sanitizer or real-card integration tests.
