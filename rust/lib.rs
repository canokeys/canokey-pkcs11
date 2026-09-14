//! Private synchronous C adapter. PKCS#11 owns transport, transactions and login.
#![deny(missing_docs)]

use canokey_protocol::{
    operation::{conversation, Continuation, LogicalCommand},
    ApduHeader, ExpectedLength, OperationOptions, SecretBytes, Step,
};
use std::{
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr, slice,
};

const OK: u32 = 0;
const ARGUMENT: u32 = 1;
const TRANSPORT: u32 = 2;
const SMALL: u32 = 3;
const FAILED: u32 = 4;
const BUDGET: usize = 4096 * 255;

/// Return the linked libcanokey C ABI revision. This keeps the Cargo static
/// library wired to the PIV C ABI while the PKCS#11 transport migration remains
/// incremental; no profile, operation, or card state crosses this boundary.
#[no_mangle]
pub extern "C" fn cnk_libcanokey_abi_version() -> u32 {
    canokey_c::cnk_abi_version()
}

/// Probe a PIV-capable device through the caller's synchronous transport.
/// The transport transaction and connection remain owned by C; the returned
/// profile is immutable and must be released with `cnk_profile_free`.
///
/// # Safety
/// `out` and `response` must be writable for their declared ranges. The
/// callback must be valid for the call, retain no pointers, and not unwind.
/// The caller must keep the card transaction alive for the complete probe.
#[no_mangle]
pub unsafe extern "C" fn cnk_profile_probe(
    transmit: Option<Transmit>,
    context: *mut c_void,
    response: *mut u8,
    response_capacity: usize,
    out: *mut *mut canokey_c::CnkProfile,
) -> u32 {
    if transmit.is_none() || response.is_null() || out.is_null() || response_capacity < 3 {
        return ARGUMENT;
    }
    *out = ptr::null_mut();
    let mut operation: *mut canokey_c::CnkOperation = ptr::null_mut();
    let mut error = canokey_c::CnkError {
        struct_size: std::mem::size_of::<canokey_c::CnkError>() as u32,
        kind: 0,
        phase: 0,
        reference: 0,
        presence_flags: 0,
        status_word: 0,
        retries_remaining: 0,
        reserved: 0,
    };
    if canokey_c::cnk_probe_device_new(1, ptr::null(), &mut operation, &mut error) != 0 {
        return FAILED;
    }
    let mut step = 0u32;
    let mut exchange = vec![0u8; response_capacity];
    loop {
        let status = if step == 0 {
            canokey_c::cnk_operation_start(operation, &mut step, &mut error)
        } else {
            let mut command_len = 0usize;
            let command_status =
                canokey_c::cnk_operation_command(operation, ptr::null_mut(), &mut command_len);
            if command_status != 0 || command_len == 0 {
                FAILED
            } else {
                let mut command = vec![0u8; command_len];
                let mut actual = command_len;
                if canokey_c::cnk_operation_command(operation, command.as_mut_ptr(), &mut actual)
                    != 0
                {
                    FAILED
                } else {
                    let mut response_len = exchange.len();
                    let callback = transmit.unwrap();
                    let transport_status = callback(
                        context,
                        command.as_ptr(),
                        actual,
                        exchange.as_mut_ptr(),
                        &mut response_len,
                    );
                    if transport_status != 0 {
                        TRANSPORT
                    } else {
                        canokey_c::cnk_operation_advance(
                            operation,
                            exchange.as_ptr(),
                            response_len,
                            &mut step,
                            &mut error,
                        )
                    }
                }
            }
        };
        if status != 0 {
            canokey_c::cnk_operation_free(operation);
            return status;
        }
        if step == 2 {
            let status = canokey_c::cnk_operation_take_profile(operation, out);
            canokey_c::cnk_operation_free(operation);
            return if status == 0 { OK } else { FAILED };
        }
    }
}

/// Copied command descriptor; layout is shared with backend/protocol.h.
#[repr(C)]
pub struct Command {
    /// CLA, INS, P1, P2.
    pub header: [u8; 4],
    /// Borrowed command data, nullable only when data_len is zero.
    pub data: *const u8,
    /// Number of input bytes, at most one MiB.
    pub data_len: usize,
    /// Zero for absent Le, otherwise 1..=256.
    pub le: u32,
    /// Allow short command chaining (zero or one).
    pub chain: u32,
    /// Follow ISO GET RESPONSE (zero or one).
    pub get_response: u32,
}

/// Synchronous raw transport, zero on success. Never retain buffers or unwind.
pub type Transmit = unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, *mut usize) -> u32;

/// Execute one logical command without selecting or releasing the caller's card.
///
/// Returns the private status in protocol.h. No output bytes are copied until
/// completion; a short buffer receives the required length including status.
/// Protocol/transport failures drop all Rust working state without replay.
/// Unwindable panics are contained; allocation failure follows Rust's OOM policy.
///
/// # Safety
/// All non-null pointers must be aligned and valid for their declared lengths.
/// Inputs and callback state must not alias outputs. The callback must initialize
/// at most its input capacity, report the actual length, and retain no pointers.
/// Serialize use of the card and keep its transaction alive across this call.
#[no_mangle]
pub unsafe extern "C" fn cnk_protocol_run(
    command: *const Command,
    transmit: Option<Transmit>,
    context: *mut c_void,
    response: *mut u8,
    response_len: *mut usize,
) -> u32 {
    catch_unwind(AssertUnwindSafe(|| {
        if command.is_null() || response.is_null() || response_len.is_null() {
            return ARGUMENT;
        }
        let Some(transmit) = transmit else {
            return ARGUMENT;
        };
        let command = unsafe { &*command };
        if command.data_len > BUDGET
            || (command.data_len != 0 && command.data.is_null())
            || command.le > 256
            || command.chain > 1
            || command.get_response > 1
        {
            return ARGUMENT;
        }
        let data = if command.data_len == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(command.data, command.data_len) }.to_vec()
        };
        let [cla, ins, p1, p2] = command.header;
        let mut logical = LogicalCommand::new(
            ApduHeader::new(cla, ins, p1, p2),
            data,
            if command.le == 0 {
                ExpectedLength::Absent
            } else {
                ExpectedLength::Exact(command.le)
            },
        );
        logical.allow_chaining = command.chain != 0;
        logical.continuation = if command.get_response != 0 {
            Continuation::Iso7816 { cla: 0 }
        } else {
            Continuation::None
        };
        // No Le correction: credential submissions and writes must never replay.
        let capacity = unsafe { *response_len };
        let mut options = OperationOptions::default();
        options.exchange.max_response_bytes = capacity.clamp(258, 65538);
        let mut physical = vec![0u8; options.exchange.max_response_bytes];
        // Wipe the allocation even on transport errors or Rust unwinding.
        let mut operation = match conversation(logical, options) {
            Ok(operation) => operation,
            Err(_) => return ARGUMENT,
        };
        let mut step = match operation.start() {
            Ok(step) => step,
            Err(_) => return FAILED,
        };
        while step == Step::Exchange {
            let command = match operation.command() {
                Ok(command) => command,
                Err(_) => return FAILED,
            };
            let mut length = physical.len();
            let status = unsafe {
                transmit(
                    context,
                    command.as_bytes().as_ptr(),
                    command.as_bytes().len(),
                    physical.as_mut_ptr(),
                    &mut length,
                )
            };
            // Move the entire allocation into zeroizing storage before any exit.
            let protected = SecretBytes::new(physical);
            if status != 0 {
                return TRANSPORT;
            }
            if length > protected.len() {
                return FAILED;
            }
            step = match operation.advance(&protected.as_bytes()[..length]) {
                Ok(step) => step,
                Err(_) => return FAILED,
            };
            if step == Step::Exchange {
                physical = vec![0u8; options.exchange.max_response_bytes];
            } else {
                physical = Vec::new();
            }
        }
        let result = match operation.take_result() {
            Ok(result) => result,
            Err(_) => return FAILED,
        };
        let needed = result.data.len() + 2;
        unsafe { *response_len = needed };
        if capacity < needed {
            return SMALL;
        }
        unsafe {
            ptr::copy_nonoverlapping(result.data.as_bytes().as_ptr(), response, result.data.len());
            ptr::copy_nonoverlapping(
                result.status.raw().to_be_bytes().as_ptr(),
                response.add(result.data.len()),
                2,
            );
        }
        OK
    }))
    .unwrap_or(FAILED)
}

#[cfg(test)]
mod tests;
