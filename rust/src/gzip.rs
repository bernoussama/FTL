// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! gzip (RFC 1952) for `pihole-FTL gzip`, `gunzip` and the teleporter import.
//! Phase 3 module: replaces inflate_buffer() and deflate_buffer() in
//! src/zip/gzip.c. The C versions stay in that file as inflate_buffer_c() and
//! deflate_buffer_c(), the reference for pihole-FTL rust-compare gzip. The
//! DEFLATE codec is miniz_oxide, the Rust port of the miniz that C uses. The
//! archive is untrusted input, so every size is checked before it is used.
//!
//! Decompression keeps the checks, their order and the log messages of the C
//! code (see Error::message()). Three C behaviours are kept on purpose: ISIZE
//! only sizes the output buffer (the decoded length is not compared with it),
//! bytes between the end of the DEFLATE stream and the footer are ignored, and
//! a stream with FHCRC set is rejected, as the header CRC is not checked.

#[cfg(test)]
mod tests;

use std::alloc::{alloc_zeroed, Layout};
use std::slice;

use miniz_oxide::inflate::stream::{inflate as inflate_stream, InflateState};
use miniz_oxide::{DataFormat, MZError, MZFlush, MZStatus};

use crate::buf::FtlRsBuf;

/// The fixed part of the header, and the footer (CRC-32 and ISIZE)
const HEADER_LEN: usize = 10;
const FOOTER_LEN: usize = 8;

/// Header flags (RFC 1952 section 2.3.1). FTEXT needs no check
const FHCRC: u8 = 0x02;
const FEXTRA: u8 = 0x04;
const FNAME: u8 = 0x08;
const FCOMMENT: u8 = 0x10;

/// Z_BEST_COMPRESSION, the level of the C deflate_buffer()
const LEVEL: u8 = 9;

/// The largest ISIZE accepted (the C limit), so the output is at most 256 MiB
const MAX_OUTPUT: usize = 0x1000_0000;

/// Why a stream is rejected. message() is the text FTL logs for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Shorter than a header and a footer, or without the gzip magic
    NotGzip,
    /// The compression method is not deflate
    Method,
    /// FHCRC is set. The header CRC is not checked, so C rejects the stream
    HeaderCrc,
    /// The extra field does not end before the footer
    Extra,
    /// The file name runs into the footer
    NameOverrun,
    /// The file name is not terminated before the footer
    NameUnterminated,
    /// The file comment runs into the footer
    CommentOverrun,
    /// The file comment is not terminated before the footer
    CommentUnterminated,
    /// ISIZE is zero or above MAX_OUTPUT
    Size,
    /// The output buffer of this many bytes cannot be allocated
    Alloc(usize),
    /// The DEFLATE data is corrupt, or it ends before the stream does
    Data,
    /// The DEFLATE output does not fit in ISIZE bytes
    Buf,
    /// The CRC-32 of the output does not match the footer
    Checksum,
}

impl Error {
    /// The text FTL logs for the error: the C log texts, unchanged. For a
    /// miniz error the C text is "Failed to uncompress: <mz_error>".
    pub fn message(self) -> String {
        match self {
            Error::NotGzip => String::from("This is not a valid GZIP stream"),
            Error::Method => String::from("Compression algorithm not supported"),
            Error::HeaderCrc => String::from("Compression with extra fields not supported"),
            Error::Extra => String::from("Invalid GZIP header"),
            Error::NameOverrun => String::from("GZIP file name field overruns into the footer"),
            Error::NameUnterminated => String::from("File name is missing or invalid in GZIP header"),
            Error::CommentOverrun => String::from("GZIP file comment field overruns into the footer"),
            Error::CommentUnterminated => String::from("File comment is missing or invalid in GZIP header"),
            Error::Size => String::from("File is empty or too large"),
            Error::Alloc(size) => format!("Failed to allocate {size} bytes of memory"),
            Error::Data => String::from("Failed to uncompress: data error"),
            Error::Buf => String::from("Failed to uncompress: buf error"),
            Error::Checksum => String::from("Checksum mismatch"),
        }
    }
}

/// Decompresses a gzip stream, as C inflate_buffer() does. A stream with ISIZE 0
/// is rejected with Size, as in C.
pub fn inflate(input: &[u8]) -> Result<Vec<u8>, Error> {
    let len = input.len();
    // From here on len >= 18, so the fixed header and the footer are in bounds
    if len < HEADER_LEN + FOOTER_LEN || input[0] != 0x1f || input[1] != 0x8b {
        return Err(Error::NotGzip);
    }
    if input[2] != 8 {
        return Err(Error::Method);
    }
    let flags = input[3];
    if flags & FHCRC != 0 {
        return Err(Error::HeaderCrc);
    }

    // The DEFLATE data runs from start to the footer. Each optional field sits
    // in front of it, so skipping one moves start past it
    let footer = len - FOOTER_LEN;
    let mut start = HEADER_LEN;
    if flags & FEXTRA != 0 {
        let xlen = usize::from(u16::from_le_bytes([input[10], input[11]]));
        if len < HEADER_LEN + 2 + xlen + FOOTER_LEN {
            return Err(Error::Extra);
        }
        start = HEADER_LEN + 2 + xlen;
    }
    if flags & FNAME != 0 {
        start = skip_zero_terminated(input, start, footer, Error::NameOverrun, Error::NameUnterminated)?;
    }
    if flags & FCOMMENT != 0 {
        start = skip_zero_terminated(input, start, footer, Error::CommentOverrun, Error::CommentUnterminated)?;
    }

    let out_len = le32(input, footer + 4) as usize;
    if out_len == 0 || out_len > MAX_OUTPUT {
        return Err(Error::Size);
    }
    let crc = le32(input, footer);
    let deflate = input.get(start..footer).ok_or(Error::Data)?;

    let mut output = zeroed(out_len).ok_or(Error::Alloc(out_len))?;
    let written = decode(deflate, &mut output)?;
    output.truncate(written);
    if crc32(&output) != crc {
        return Err(Error::Checksum);
    }
    Ok(output)
}

/// Compresses data into a gzip stream with mtime in the header, as C
/// deflate_buffer() does: FTEXT, XFL 2 (maximum compression) and OS 3 (Unix).
pub fn deflate(data: &[u8], mtime: u32) -> Vec<u8> {
    let body = miniz_oxide::deflate::compress_to_vec(data, LEVEL);
    let mut stream = Vec::with_capacity(HEADER_LEN + body.len() + FOOTER_LEN);
    stream.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x01]);
    stream.extend_from_slice(&mtime.to_le_bytes());
    stream.extend_from_slice(&[0x02, 0x03]);
    stream.extend_from_slice(&body);
    stream.extend_from_slice(&crc32(data).to_le_bytes());
    // ISIZE is the length modulo 2^32, as RFC 1952 defines it
    stream.extend_from_slice(&(data.len() as u32).to_le_bytes());
    stream
}

/// Skips the zero-terminated field (FNAME or FCOMMENT) that starts at start and
/// returns the position after its terminator. The terminator has to lie before
/// the footer, which starts at footer.
fn skip_zero_terminated(
    input: &[u8],
    start: usize,
    footer: usize,
    overrun: Error,
    unterminated: Error,
) -> Result<usize, Error> {
    if start >= footer {
        return Err(overrun);
    }
    match input[start..footer].iter().position(|&byte| byte == 0) {
        Some(at) => Ok(start + at + 1),
        None => Err(unterminated),
    }
}

/// Decodes raw DEFLATE data into out, as C mz_uncompress2_raw() does: the stream
/// has to end within out. Returns the number of bytes written.
fn decode(deflate: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    let mut state = InflateState::new_boxed(DataFormat::Raw);
    let result = inflate_stream(&mut state, deflate, out, MZFlush::Finish);
    match result.status {
        Ok(MZStatus::StreamEnd) => Ok(result.bytes_written),
        // As in C, a buffer error with no input left is reported as a data error
        Err(MZError::Buf) if result.bytes_consumed == deflate.len() => Err(Error::Data),
        Err(MZError::Buf) => Err(Error::Buf),
        // Corrupt data. A single Finish call returns nothing else
        _ => Err(Error::Data),
    }
}

/// A zeroed Vec of len bytes, or None if the allocation fails. The allocator
/// hands out zeroed pages lazily, so a large ISIZE costs little until the
/// decoder writes to the output.
fn zeroed(len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    let layout = Layout::array::<u8>(len).ok()?;
    // SAFETY: the layout has a non-zero size. A non-null pointer addresses len
    // zeroed bytes, and it comes from the global allocator with the layout of a
    // Vec<u8> of capacity len, so the Vec frees it correctly.
    unsafe {
        let ptr = alloc_zeroed(layout);
        (!ptr.is_null()).then(|| Vec::from_raw_parts(ptr, len, len))
    }
}

/// The little-endian u32 at offset at. The caller keeps at + 4 within bounds.
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// CRC-32 (ISO 3309, the reflected polynomial 0xEDB88320) of data
fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &byte| {
        CRC_TABLE[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8)
    })
}

const CRC_TABLE: [u32; 256] = crc_table();

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            bit += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

/// The input bytes as a slice: empty for len 0, None for a NULL pointer or a
/// length no slice can have
///
/// # Safety
/// data must be NULL or point to len readable bytes.
unsafe fn borrow_input<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if data.is_null() || len > isize::MAX as usize {
        None
    } else {
        Some(slice::from_raw_parts(data, len))
    }
}

/// Decompresses the gzip stream of len bytes at data, as C inflate_buffer() does.
/// On success writes the output to *out and returns true, leaving *message
/// alone. On failure writes the text FTL logs to *message and returns false,
/// leaving *out alone. The buffer that is written is released with
/// ftl_rs_buf_free(). data may be NULL if len is 0.
///
/// Locks: none. Never panics.
///
/// # Safety
/// data must be NULL or point to len readable bytes. out and message must not be
/// NULL and must point to ftl_rs_buf structs that C owns. The one that is written
/// is overwritten, not freed.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_gzip_inflate(
    data: *const u8,
    len: usize,
    out: *mut FtlRsBuf,
    message: *mut FtlRsBuf,
) -> bool {
    if out.is_null() || message.is_null() {
        return false;
    }
    match borrow_input(data, len).map_or(Err(Error::NotGzip), inflate) {
        Ok(output) => {
            *out = FtlRsBuf::from_vec(output);
            true
        }
        Err(error) => {
            *message = FtlRsBuf::from_vec(error.message().into_bytes());
            false
        }
    }
}

/// Compresses the len bytes at data into a gzip stream with the given mtime, as
/// C deflate_buffer() does. On success writes the stream to *out, to be released
/// with ftl_rs_buf_free(), and returns true. Returns false, leaving *out alone,
/// if data is NULL and len is not 0.
///
/// Locks: none. Never panics.
///
/// # Safety
/// data must be NULL or point to len readable bytes. out must not be NULL and
/// must point to an ftl_rs_buf that C owns. It is overwritten, not freed.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_gzip_deflate(data: *const u8, len: usize, mtime: u32, out: *mut FtlRsBuf) -> bool {
    if out.is_null() {
        return false;
    }
    match borrow_input(data, len) {
        Some(bytes) => {
            *out = FtlRsBuf::from_vec(deflate(bytes, mtime));
            true
        }
        None => false,
    }
}
