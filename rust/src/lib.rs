// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Phase 1 toolchain spike: an empty library that proves a Rust static
//! library builds and links into the statically linked pihole-FTL on every
//! CI architecture. The C side is declared in src/ftl_rs.h.

use std::ffi::c_char;

/// Bumped whenever a function or type crossing the C/Rust boundary changes.
/// The C side compares it with FTL_RS_ABI_VERSION from src/ftl_rs.h.
pub const ABI_VERSION: u32 = 1;

/// ABI version this library was built with.
///
/// Locks: none. Never panics.
#[no_mangle]
pub extern "C" fn ftl_rs_abi_version() -> u32 {
    ABI_VERSION
}

/// NUL-terminated library version, e.g. "0.1.0". Static, must not be freed.
///
/// Locks: none. Never panics.
#[no_mangle]
pub extern "C" fn ftl_rs_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn version_is_nul_terminated_package_version() {
        let v = unsafe { CStr::from_ptr(ftl_rs_version()) };
        assert_eq!(v.to_str().unwrap(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn abi_version_matches_constant() {
        assert_eq!(ftl_rs_abi_version(), ABI_VERSION);
    }
}
