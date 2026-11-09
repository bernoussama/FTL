// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! tar archive reader for the v5 teleporter import (find and list files).
//! Phase 3 module: replaces find_file_in_tar() and list_files_in_tar() in
//! src/zip/tar.c. Parses untrusted uploads.
//!
//! The rules are those of tar.c. Headers are read one 512-byte block after
//! another from the start, and the walk ends at the first block that is not a
//! header, so a missing end-of-archive block is fine. A header needs the
//! "ustar" magic, a size field that parses and fits in usize, and a NUL inside
//! its 100-byte name field. The header checksum is not checked, as in tar.c.
//! No byte past the end of the archive is read, and no allocation depends on a
//! size field.

use std::ffi::c_char;
use std::mem::size_of;
use std::slice;

use crate::buf::FtlRsBuf;

/// Bytes per block. Headers and data are whole blocks.
const BLOCK: usize = 512;
/// Length of the name field. A name ends with a NUL inside this field.
const NAME_LEN: usize = 100;
/// Offset and length of the octal size field
const SIZE_OFFSET: usize = 124;
const SIZE_LEN: usize = 12;
/// Offset of the magic. As in tar.c, only its first five bytes are compared.
const MAGIC_OFFSET: usize = 257;
const MAGIC: &[u8] = b"ustar";
/// Bytes of one entry in the buffer of ftl_rs_tar_list(): the offset and the
/// size, both usize in native byte order (ftl_rs_tar_entry in src/ftl_rs.h)
const RECORD_LEN: usize = 2 * size_of::<usize>();

/// An entry as list_entries() gives it: the offset of its header block in the
/// archive and the size of its data. The name is the NUL-terminated string at
/// the offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub offset: usize,
    pub size: usize,
}

/// A header that tar.c accepts
struct Header<'a> {
    /// The name, without its NUL
    name: &'a [u8],
    size: usize,
    /// Bytes from this header to the next one: see entry_span()
    span: usize,
    /// Bytes of the archive after the header block
    room: usize,
}

/// Reads the header at `pos` as tar.c does. None where tar.c stops: fewer than
/// BLOCK bytes are left, the magic is not "ustar", the size field does not
/// parse or does not fit, or the name has no NUL in its field.
fn header_at(tar: &[u8], pos: usize) -> Option<Header<'_>> {
    let block = tar.get(pos..)?.get(..BLOCK)?;
    if &block[MAGIC_OFFSET..MAGIC_OFFSET + MAGIC.len()] != MAGIC {
        return None;
    }
    let size = parse_size(&block[SIZE_OFFSET..SIZE_OFFSET + SIZE_LEN])?;
    let span = entry_span(size)?;
    let name_field = &block[..NAME_LEN];
    let name_len = name_field.iter().position(|&byte| byte == 0)?;
    Some(Header {
        name: &name_field[..name_len],
        size,
        span,
        room: tar.len() - (pos + BLOCK),
    })
}

/// The size in an octal header field, read as parse_tar_size() in tar.c reads
/// it: spaces before the first digit are skipped, then come the digits 0 to 7,
/// after which only spaces and NULs may follow. At least one digit is needed,
/// and the value must fit in usize.
fn parse_size(field: &[u8]) -> Option<usize> {
    let mut parsed: usize = 0;
    let mut seen_digit = false;
    let mut trailing = false;
    for &byte in field {
        match byte {
            b' ' => trailing |= seen_digit,
            b'\0' if seen_digit => trailing = true,
            b'\0' => return None,
            b'0'..=b'7' if !trailing => {
                let digit = usize::from(byte - b'0');
                parsed = parsed.checked_mul(8)?.checked_add(digit)?;
                seen_digit = true;
            }
            _ => return None,
        }
    }
    seen_digit.then_some(parsed)
}

/// The bytes an entry takes: its header block plus its data rounded up to
/// whole blocks. None if that does not fit in usize (tar_entry_span() in tar.c).
fn entry_span(size: usize) -> Option<usize> {
    let data_blocks = size.checked_add(BLOCK - 1)? / BLOCK;
    data_blocks.checked_mul(BLOCK)?.checked_add(BLOCK)
}

/// The header that follows an entry at `pos` that spans `span` bytes, if it
/// lies inside an archive of `len` bytes. An entry that runs past the end ends
/// the walk.
fn next_header(len: usize, pos: usize, span: usize) -> Option<usize> {
    let next = pos.checked_add(span)?;
    (next <= len).then_some(next)
}

/// The first entry named `name`, as find_file_in_tar() gives it: the offset of
/// its data in `tar` and its size. The walk stops at the first entry with that
/// name. If its data does not fit, the search fails there, even if a later
/// entry has the same name.
fn find_entry(tar: &[u8], name: &[u8]) -> Option<(usize, usize)> {
    let mut pos = 0;
    while let Some(header) = header_at(tar, pos) {
        if header.name == name {
            return (header.size <= header.room).then_some((pos + BLOCK, header.size));
        }
        pos = next_header(tar.len(), pos, header.span)?;
    }
    None
}

/// The entries that list_files_in_tar() lists, in archive order. An entry is
/// listed when its data fits, even if the padding after it is cut short, and
/// the walk stops after it.
fn list_entries(tar: &[u8]) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while let Some(header) = header_at(tar, pos) {
        if header.size > header.room {
            break;
        }
        entries.push(Entry {
            offset: pos,
            size: header.size,
        });
        let Some(next) = next_header(tar.len(), pos, header.span) else {
            break;
        };
        pos = next;
    }
    entries
}

/// The archive that C passes as `tar` and `tar_size`. NULL is an empty archive.
///
/// # Safety
/// `tar` is NULL, or points to `len` bytes that stay valid and unchanged for
/// the lifetime `'a`.
unsafe fn archive<'a>(tar: *const u8, len: usize) -> &'a [u8] {
    if tar.is_null() {
        &[]
    } else {
        slice::from_raw_parts(tar, len)
    }
}

/// The name that C passes, up to its NUL. None if the pointer is NULL, or if
/// there is no NUL in the first NAME_LEN bytes: a name that long matches no
/// entry, so the caller can stop there.
///
/// # Safety
/// `name` is NULL, or points to a C string. Bytes are read up to its NUL only.
unsafe fn c_name<'a>(name: *const c_char) -> Option<&'a [u8]> {
    if name.is_null() {
        return None;
    }
    let name = name.cast::<u8>();
    let len = (0..NAME_LEN).find(|&i| *name.add(i) == 0)?;
    Some(slice::from_raw_parts(name, len))
}

/// Finds the first entry named `name` in an archive, as find_file_in_tar() in
/// src/zip/tar.c does. On success returns true, and writes the offset of the
/// data in `tar` to *payload_offset and its size to *file_size. Otherwise
/// returns false and writes 0 to both. Each output is written only if its
/// pointer is not NULL.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `tar` is NULL (an empty archive), or points to `tar_size` readable bytes.
/// `name` is NULL (no match), or a NUL-terminated string. The outputs are NULL
/// or writable.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_tar_find(
    tar: *const u8,
    tar_size: usize,
    name: *const c_char,
    payload_offset: *mut usize,
    file_size: *mut usize,
) -> bool {
    let found = c_name(name).and_then(|name| find_entry(archive(tar, tar_size), name));
    if let Some(out) = payload_offset.as_mut() {
        *out = found.map_or(0, |(offset, _)| offset);
    }
    if let Some(out) = file_size.as_mut() {
        *out = found.map_or(0, |(_, size)| size);
    }
    found.is_some()
}

/// The entries of an archive, as list_files_in_tar() in src/zip/tar.c lists
/// them. The result is one ftl_rs_tar_entry record per entry, in order, each
/// the offset and the size as usize in native byte order. Free it with
/// ftl_rs_buf_free(). The result is empty for a NULL archive.
///
/// Locks: none. Never panics.
///
/// # Safety
/// As for ftl_rs_tar_find(), without `name`.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_tar_list(tar: *const u8, tar_size: usize) -> FtlRsBuf {
    let entries = list_entries(archive(tar, tar_size));
    let mut records = Vec::with_capacity(entries.len() * RECORD_LEN);
    for entry in entries {
        records.extend_from_slice(&entry.offset.to_ne_bytes());
        records.extend_from_slice(&entry.size.to_ne_bytes());
    }
    FtlRsBuf::from_vec(records)
}

#[cfg(test)]
mod tests;
