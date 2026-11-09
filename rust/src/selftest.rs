// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Exports for the hidden `pihole-FTL rust-*` test subcommands (src/args.c and
//! src/ftl_rs_selftest.c). They exercise the boundary rules and carry no FTL
//! behaviour of their own.

use crate::buf::FtlRsBuf;
use crate::fork::with_state;

/// Byte `i` of a selftest buffer. 251 is prime, so the pattern does not line
/// up with powers of two.
pub fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

/// Returns a buffer of `n` bytes with byte `i` equal to `pattern(i)`. Free it
/// with ftl_rs_buf_free().
///
/// Locks: none. Never panics.
#[no_mangle]
pub extern "C" fn ftl_rs_selftest_buf(n: usize) -> FtlRsBuf {
    FtlRsBuf::from_vec((0..n).map(pattern).collect())
}

/// Takes the process-local lock, counts a tick and returns the new count. The
/// count starts again at 1 after ftl_rs_after_fork().
///
/// Locks: takes the process-local state lock and releases it before returning.
#[no_mangle]
pub extern "C" fn ftl_rs_selftest_tick() -> u64 {
    with_state(|state| {
        state.ticks += 1;
        state.ticks
    })
}

/// Panics. With panic = "abort" the message is printed and the process aborts.
///
/// Locks: none.
#[no_mangle]
pub extern "C" fn ftl_rs_selftest_panic() -> ! {
    panic!("ftl-rs selftest panic, requested by pihole-FTL rust-panic-test")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_repeats_every_251_bytes() {
        assert_eq!(pattern(0), 0);
        assert_eq!(pattern(250), 250);
        assert_eq!(pattern(251), 0);
        assert_eq!(pattern(252), 1);
    }
}
