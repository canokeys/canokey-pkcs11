//! Static linkage for the libcanokey C ABI. C owns transport and application state.
#![deny(missing_docs)]

/// Report the linked ABI revision and retain the dependency in this static library.
#[no_mangle]
pub extern "C" fn cnk_libcanokey_abi_version() -> u32 {
    canokey_c::cnk_abi_version()
}
