// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! ZIP archive reader and writer for the teleporter (in memory). Phase 3
//! module: replaces the miniz mz_zip_* calls in src/zip/teleporter.c. Parses
//! untrusted uploads, so every offset and size is checked before it is used.
//!
//! reader.rs follows miniz's mz_zip_reader: the same checks in the same order,
//! the same error codes and the same last-error state, so the hints and logs of
//! the teleporter do not change. writer.rs writes standard archives (no data
//! descriptors, no ZIP64) that miniz and unzip read. Errors are the
//! mz_zip_error values of src/zip/miniz/miniz.h, and the declarations are in
//! src/ftl_rs.h. The differences from miniz are listed in reader.rs and
//! writer.rs.

mod crc32;
mod reader;
#[cfg(test)]
mod tests;
mod writer;

use crate::buf::FtlRsBuf;
use reader::Reader;
use std::ffi::{c_char, CStr};
use std::mem::{offset_of, size_of};
use std::ptr;
use std::slice;
use writer::Writer;

// mz_zip_error values of src/zip/miniz/miniz.h (only the ones this module uses)
pub const ERR_NONE: u32 = 0;
pub const ERR_UNDEFINED: u32 = 1;
pub const ERR_TOO_MANY_FILES: u32 = 2;
pub const ERR_FILE_TOO_LARGE: u32 = 3;
pub const ERR_UNSUPPORTED_METHOD: u32 = 4;
pub const ERR_UNSUPPORTED_ENCRYPTION: u32 = 5;
pub const ERR_UNSUPPORTED_FEATURE: u32 = 6;
pub const ERR_FAILED_FINDING_CENTRAL_DIR: u32 = 7;
pub const ERR_NOT_AN_ARCHIVE: u32 = 8;
pub const ERR_INVALID_HEADER_OR_CORRUPTED: u32 = 9;
pub const ERR_UNSUPPORTED_MULTIDISK: u32 = 10;
pub const ERR_DECOMPRESSION_FAILED: u32 = 11;
pub const ERR_UNEXPECTED_DECOMPRESSED_SIZE: u32 = 13;
pub const ERR_CRC_CHECK_FAILED: u32 = 14;
pub const ERR_UNSUPPORTED_CDIR_SIZE: u32 = 15;
pub const ERR_FILE_READ_FAILED: u32 = 20;
pub const ERR_INVALID_PARAMETER: u32 = 24;
pub const ERR_INVALID_FILENAME: u32 = 25;
pub const ERR_BUF_TOO_SMALL: u32 = 26;
pub const ERR_ARCHIVE_TOO_LARGE: u32 = 29;
pub const ERR_VALIDATION_FAILED: u32 = 30;

/// One member of an archive: the C `ftl_rs_zip_stat`, as
/// mz_zip_archive_file_stat. name and comment are NUL-terminated and cut to 511
/// bytes, as in miniz.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZipStat {
    pub method: u16,
    pub bit_flag: u16,
    pub dos_time: u16,
    pub dos_date: u16,
    pub crc32: u32,
    pub external_attr: u32,
    pub is_directory: bool,
    /// Zero. Puts comp_size at offset 24 on every ABI (i386 aligns u64 to 4 bytes)
    pub reserved: [u8; 7],
    pub comp_size: u64,
    pub uncomp_size: u64,
    pub local_header_ofs: u64,
    pub name: [u8; 512],
    pub comment: [u8; 512],
}

impl ZipStat {
    fn new() -> ZipStat {
        ZipStat {
            method: 0,
            bit_flag: 0,
            dos_time: 0,
            dos_date: 0,
            crc32: 0,
            external_attr: 0,
            is_directory: false,
            reserved: [0; 7],
            comp_size: 0,
            uncomp_size: 0,
            local_header_ofs: 0,
            name: [0; 512],
            comment: [0; 512],
        }
    }
}

/// Writes the size of `ftl_rs_zip_stat` and the offsets of is_directory,
/// comp_size, local_header_ofs, name and comment to `out[0..6]`, so C can
/// compare them with its own view (`pihole-FTL rust-version`).
///
/// Locks: none. Never panics.
///
/// # Safety
/// `out` is NULL or points to six writable `size_t`.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_stat_layout(out: *mut usize) {
    if out.is_null() {
        return;
    }
    let layout = [
        size_of::<ZipStat>(),
        offset_of!(ZipStat, is_directory),
        offset_of!(ZipStat, comp_size),
        offset_of!(ZipStat, local_header_ofs),
        offset_of!(ZipStat, name),
        offset_of!(ZipStat, comment),
    ];
    ptr::copy_nonoverlapping(layout.as_ptr(), out, layout.len());
}

/// An archive opened by ftl_rs_zip_open(). It borrows the caller's buffer.
pub struct ZipReader(Reader<'static>);

/// An archive being written by the ftl_rs_zip_writer_*() functions
pub struct ZipWriter(Writer);

/// Opens the archive of `len` bytes at `data`. On success returns 0 and writes
/// the reader to `*reader`. Otherwise returns the error and writes NULL.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `data` must point to `len` readable bytes that stay unchanged until
/// ftl_rs_zip_reader_free(). `reader` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_open(
    data: *const u8,
    len: usize,
    reader: *mut *mut ZipReader,
) -> u32 {
    let Some(reader) = reader.as_mut() else {
        return ERR_INVALID_PARAMETER;
    };
    *reader = ptr::null_mut();
    if data.is_null() || len > isize::MAX as usize {
        return ERR_INVALID_PARAMETER;
    }
    // The caller keeps the buffer for as long as the reader lives (see Safety)
    let bytes: &'static [u8] = slice::from_raw_parts(data, len);
    match Reader::open(bytes) {
        Ok(r) => {
            *reader = Box::into_raw(Box::new(ZipReader(r)));
            ERR_NONE
        }
        Err(code) => code,
    }
}

/// The number of members of an archive. 0 for NULL.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `reader` must be NULL or a reader from ftl_rs_zip_open() that is not freed.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_num_files(reader: *const ZipReader) -> u32 {
    reader.as_ref().map_or(0, |r| r.0.num_files())
}

/// Writes the stat of member `index` to `stat`. Returns false on error, and the
/// error is then the last error of the reader.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `reader` must be NULL or a live reader. `stat` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_file_stat(
    reader: *const ZipReader,
    index: u32,
    stat: *mut ZipStat,
) -> bool {
    let (Some(reader), Some(stat)) = (reader.as_ref(), stat.as_mut()) else {
        return false;
    };
    match reader.0.file_stat(index) {
        Some(s) => {
            *stat = s;
            true
        }
        None => false,
    }
}

/// Writes the uncompressed data of member `index` into `buf`, which must hold
/// at least the member's uncompressed size. Returns false on error.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `reader` must be NULL or a live reader. `buf` must be NULL or point to
/// `buf_size` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_extract(
    reader: *const ZipReader,
    index: u32,
    buf: *mut u8,
    buf_size: usize,
) -> bool {
    let Some(reader) = reader.as_ref() else {
        return false;
    };
    if (buf.is_null() && buf_size != 0) || buf_size > isize::MAX as usize {
        reader.0.set_error(ERR_INVALID_PARAMETER);
        return false;
    }
    let out: &mut [u8] = if buf_size == 0 {
        &mut []
    } else {
        slice::from_raw_parts_mut(buf, buf_size)
    };
    reader.0.extract(index, out)
}

/// Returns the last error of the reader and clears it. 0 for NULL.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `reader` must be NULL or a live reader.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_last_error(reader: *const ZipReader) -> u32 {
    reader.as_ref().map_or(ERR_NONE, |r| r.0.take_error())
}

/// Frees a reader from ftl_rs_zip_open(). NULL is a no-op.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `reader` must be NULL or a reader from ftl_rs_zip_open() that is not freed.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_reader_free(reader: *mut ZipReader) {
    if !reader.is_null() {
        drop(Box::from_raw(reader));
    }
}

/// Checks every member of the archive of `len` bytes at `data`. Returns 0 if it
/// is valid, otherwise the error. Memory use does not depend on the sizes the
/// archive declares.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `data` must be NULL or point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_validate(data: *const u8, len: usize) -> u32 {
    if (data.is_null() && len != 0) || len > isize::MAX as usize {
        return ERR_INVALID_PARAMETER;
    }
    let bytes: &[u8] = if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, len)
    };
    reader::validate(bytes)
}

/// Starts an empty archive. Free it with ftl_rs_zip_writer_free().
///
/// Locks: none. Never panics.
#[no_mangle]
pub extern "C" fn ftl_rs_zip_writer_new() -> *mut ZipWriter {
    Box::into_raw(Box::new(ZipWriter(Writer::new())))
}

/// Adds a member to the archive. The strings are NUL-terminated; `comment` may
/// be NULL. Returns 0, or the error with the archive unchanged.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `writer` must be NULL or a live writer. `name` and `comment` must be NULL
/// or NUL-terminated. `data` must be NULL with `len` 0, or point to `len`
/// readable bytes.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_writer_add(
    writer: *mut ZipWriter,
    name: *const c_char,
    data: *const u8,
    len: usize,
    comment: *const c_char,
    dos_time: u16,
    dos_date: u16,
) -> u32 {
    let Some(writer) = writer.as_mut() else {
        return ERR_INVALID_PARAMETER;
    };
    if name.is_null() || (data.is_null() && len != 0) || len > isize::MAX as usize {
        return ERR_INVALID_PARAMETER;
    }
    let name = CStr::from_ptr(name).to_bytes();
    let comment = if comment.is_null() {
        &[][..]
    } else {
        CStr::from_ptr(comment).to_bytes()
    };
    let data: &[u8] = if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, len)
    };
    match writer.0.add(name, data, comment, dos_time, dos_date) {
        Ok(()) => ERR_NONE,
        Err(code) => code,
    }
}

/// Writes the finished archive into `out`, which the caller releases with
/// ftl_rs_buf_free(). Returns 0, or the error with `out` untouched. The writer
/// takes no more members after this call.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `writer` must be NULL or a live writer. `out` must be NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_writer_finish(
    writer: *mut ZipWriter,
    out: *mut FtlRsBuf,
) -> u32 {
    let (Some(writer), Some(out)) = (writer.as_mut(), out.as_mut()) else {
        return ERR_INVALID_PARAMETER;
    };
    match writer.0.finish() {
        Ok(bytes) => {
            *out = FtlRsBuf::from_vec(bytes);
            ERR_NONE
        }
        Err(code) => code,
    }
}

/// Frees a writer from ftl_rs_zip_writer_new(). NULL is a no-op.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `writer` must be NULL or a writer from ftl_rs_zip_writer_new() that is not
/// freed.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_zip_writer_free(writer: *mut ZipWriter) {
    if !writer.is_null() {
        drop(Box::from_raw(writer));
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::mem::{align_of, offset_of, size_of};

    #[test]
    fn stat_layout_matches_the_c_struct() {
        assert_eq!(size_of::<ZipStat>(), 1072);
        assert_eq!(align_of::<ZipStat>(), align_of::<u64>());
        assert_eq!(offset_of!(ZipStat, method), 0);
        assert_eq!(offset_of!(ZipStat, crc32), 8);
        assert_eq!(offset_of!(ZipStat, external_attr), 12);
        assert_eq!(offset_of!(ZipStat, is_directory), 16);
        assert_eq!(offset_of!(ZipStat, reserved), 17);
        assert_eq!(offset_of!(ZipStat, comp_size), 24);
        assert_eq!(offset_of!(ZipStat, uncomp_size), 32);
        assert_eq!(offset_of!(ZipStat, local_header_ofs), 40);
        assert_eq!(offset_of!(ZipStat, name), 48);
        assert_eq!(offset_of!(ZipStat, comment), 560);
    }
}
