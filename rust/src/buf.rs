// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Byte buffers that Rust allocates and hands to C. C releases them with
//! ftl_rs_buf_free() and never calls free() on them.

use std::mem::{offset_of, size_of, ManuallyDrop};
use std::ptr;

/// The C `ftl_rs_buf` of src/ftl_rs.h. `ptr` holds `len` initialised bytes
/// inside an allocation of `cap` bytes, or is NULL when there is none.
#[repr(C)]
pub struct FtlRsBuf {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

impl FtlRsBuf {
    const EMPTY: FtlRsBuf = FtlRsBuf {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };

    /// Hands the allocation of `v` over to C. A Vec without capacity has no
    /// allocation, so the result is EMPTY.
    pub fn from_vec(v: Vec<u8>) -> FtlRsBuf {
        if v.capacity() == 0 {
            return FtlRsBuf::EMPTY;
        }
        let mut v = ManuallyDrop::new(v);
        FtlRsBuf {
            ptr: v.as_mut_ptr(),
            len: v.len(),
            cap: v.capacity(),
        }
    }
}

/// Frees a buffer from `FtlRsBuf::from_vec()` and resets it to NULL/0/0.
/// NULL, and a buffer that is already freed, are no-ops.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `buf` must be NULL or point to an `ftl_rs_buf` that C owns, unchanged
/// since Rust returned it.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_buf_free(buf: *mut FtlRsBuf) {
    let Some(buf) = buf.as_mut() else {
        return;
    };
    if !buf.ptr.is_null() {
        drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
    }
    *buf = FtlRsBuf::EMPTY;
}

/// Writes the size of `ftl_rs_buf` and the offsets of its ptr, len and cap
/// fields to `out[0..4]`, so C can compare them with its own view.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `out` must be NULL or point to four writable `size_t`.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_buf_layout(out: *mut usize) {
    if out.is_null() {
        return;
    }
    let layout = [
        size_of::<FtlRsBuf>(),
        offset_of!(FtlRsBuf, ptr),
        offset_of!(FtlRsBuf, len),
        offset_of!(FtlRsBuf, cap),
    ];
    ptr::copy_nonoverlapping(layout.as_ptr(), out, layout.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selftest::{ftl_rs_selftest_buf, pattern};
    use std::mem::align_of;

    #[test]
    fn layout_matches_the_c_struct() {
        let pointer = size_of::<*mut u8>();
        assert_eq!(size_of::<FtlRsBuf>(), pointer + 2 * size_of::<usize>());
        assert_eq!(align_of::<FtlRsBuf>(), align_of::<*mut u8>());
        assert_eq!(offset_of!(FtlRsBuf, ptr), 0);
        assert_eq!(offset_of!(FtlRsBuf, len), pointer);
        assert_eq!(offset_of!(FtlRsBuf, cap), pointer + size_of::<usize>());
    }

    #[test]
    fn layout_export_writes_size_and_offsets() {
        let mut out = [0usize; 4];
        unsafe { ftl_rs_buf_layout(out.as_mut_ptr()) };
        let pointer = size_of::<*mut u8>();
        assert_eq!(
            out,
            [
                size_of::<FtlRsBuf>(),
                0,
                pointer,
                pointer + size_of::<usize>()
            ]
        );
        // NULL is accepted and does nothing
        unsafe { ftl_rs_buf_layout(ptr::null_mut()) };
    }

    #[test]
    fn free_releases_the_buffer_and_resets_it() {
        let mut buf = ftl_rs_selftest_buf(1000);
        assert_eq!(buf.len, 1000);
        assert!(buf.cap >= 1000);
        for i in 0..buf.len {
            assert_eq!(unsafe { *buf.ptr.add(i) }, pattern(i));
        }
        unsafe { ftl_rs_buf_free(&mut buf) };
        assert!(buf.ptr.is_null());
        assert_eq!((buf.len, buf.cap), (0, 0));
        // A second free and a NULL pointer are both no-ops
        unsafe { ftl_rs_buf_free(&mut buf) };
        unsafe { ftl_rs_buf_free(ptr::null_mut()) };
    }

    #[test]
    fn empty_buffer_has_no_allocation() {
        let mut buf = ftl_rs_selftest_buf(0);
        assert!(buf.ptr.is_null());
        assert_eq!((buf.len, buf.cap), (0, 0));
        unsafe { ftl_rs_buf_free(&mut buf) };
    }
}
