// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Writes a ZIP archive into memory with the layout the teleporter has always
//! produced with miniz's mz_zip_writer: data of up to 3 bytes is stored, other
//! data is deflated (level 9), names are UTF-8 (flag 0x0800), there are no data
//! descriptors, no extra fields and no archive comment. DOS time and date come
//! from the caller, which converts them in C.
//!
//! Differences from miniz, see also zip.rs:
//! - miniz switches to ZIP64 at 65535 members and at 4 GiB; this writer refuses
//!   more than 65535 members (TOO_MANY_FILES) and any offset above 4 GiB
//!   (ARCHIVE_TOO_LARGE). The teleporter never gets near either limit.
//! - the local and central headers of stored members say "version needed 0", as
//!   miniz does; deflated members say 20.

use super::crc32::crc32;
use super::reader::{CDH_LEN, CDH_SIG, EOCD_LEN, EOCD_SIG, LDH_SIG, METHOD_DEFLATED, METHOD_STORED};
use super::{
    ERR_ARCHIVE_TOO_LARGE, ERR_FILE_TOO_LARGE, ERR_INVALID_FILENAME, ERR_INVALID_PARAMETER,
    ERR_TOO_MANY_FILES, ERR_UNSUPPORTED_CDIR_SIZE,
};
use miniz_oxide::deflate::compress_to_vec;

/// Data of up to this many bytes is stored, not deflated (miniz's rule)
const STORE_MAX: usize = 3;
/// The deflate level the teleporter used with miniz
const DEFLATE_LEVEL: u8 = 9;
/// General purpose flag: names are UTF-8
const FLAG_UTF8: u16 = 0x0800;
/// The DOS directory attribute, set for names ending in '/'
const DOS_DIRECTORY: u32 = 0x10;
/// "Version made by" and "version needed" for deflated members (miniz writes 20)
const VERSION: u16 = 20;

struct Entry {
    name: Vec<u8>,
    comment: Vec<u8>,
    method: u16,
    external_attr: u32,
    crc32: u32,
    comp_size: u32,
    uncomp_size: u32,
    dos_time: u16,
    dos_date: u16,
    local_ofs: u32,
}

/// An archive being written. `finish` returns its bytes once.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
    entries: Vec<Entry>,
    finished: bool,
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    /// Adds one member: its local header, its data, and its central record at
    /// `finish`. Errors leave the archive as it was.
    pub fn add(
        &mut self,
        name: &[u8],
        data: &[u8],
        comment: &[u8],
        dos_time: u16,
        dos_date: u16,
    ) -> Result<(), u32> {
        if self.finished {
            return Err(ERR_INVALID_PARAMETER);
        }
        // Names are checked as miniz checks them: no leading '/', at most 65535 bytes
        if name.first() == Some(&b'/') || name.len() > usize::from(u16::MAX) {
            return Err(ERR_INVALID_FILENAME);
        }
        if comment.len() > usize::from(u16::MAX) {
            return Err(ERR_INVALID_PARAMETER);
        }
        // A directory (name ends in '/') carries no data
        let is_dir = name.last() == Some(&b'/');
        if is_dir && !data.is_empty() {
            return Err(ERR_INVALID_PARAMETER);
        }
        let uncomp_size = u32::try_from(data.len()).map_err(|_| ERR_FILE_TOO_LARGE)?;
        // Offsets are 32-bit without ZIP64
        let local_ofs = u32::try_from(self.buf.len()).map_err(|_| ERR_ARCHIVE_TOO_LARGE)?;

        let deflated;
        let (method, body): (u16, &[u8]) = if data.len() <= STORE_MAX {
            (METHOD_STORED, data)
        } else {
            deflated = compress_to_vec(data, DEFLATE_LEVEL);
            (METHOD_DEFLATED, deflated.as_slice())
        };
        let comp_size = u32::try_from(body.len()).map_err(|_| ERR_ARCHIVE_TOO_LARGE)?;
        let crc = crc32(data);
        let version = if method == METHOD_STORED { 0 } else { VERSION };

        // Local file header, name, then the data
        self.buf.extend_from_slice(&LDH_SIG.to_le_bytes());
        self.buf.extend_from_slice(&version.to_le_bytes());
        self.buf.extend_from_slice(&FLAG_UTF8.to_le_bytes());
        self.buf.extend_from_slice(&method.to_le_bytes());
        self.buf.extend_from_slice(&dos_time.to_le_bytes());
        self.buf.extend_from_slice(&dos_date.to_le_bytes());
        self.buf.extend_from_slice(&crc.to_le_bytes());
        self.buf.extend_from_slice(&comp_size.to_le_bytes());
        self.buf.extend_from_slice(&uncomp_size.to_le_bytes());
        self.buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes());
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(body);

        self.entries.push(Entry {
            name: name.to_vec(),
            comment: comment.to_vec(),
            method,
            external_attr: if is_dir { DOS_DIRECTORY } else { 0 },
            crc32: crc,
            comp_size,
            uncomp_size,
            dos_time,
            dos_date,
            local_ofs,
        });
        Ok(())
    }

    /// Writes the central directory and the end record, and returns the archive.
    /// On error nothing is written and the archive can still be finished later.
    pub fn finish(&mut self) -> Result<Vec<u8>, u32> {
        if self.finished {
            return Err(ERR_INVALID_PARAMETER);
        }
        if self.entries.len() > usize::from(u16::MAX) {
            return Err(ERR_TOO_MANY_FILES);
        }
        let cdir_size: u64 = self
            .entries
            .iter()
            .map(|e| (CDH_LEN + e.name.len() + e.comment.len()) as u64)
            .sum();
        if cdir_size >= u64::from(u32::MAX) {
            return Err(ERR_UNSUPPORTED_CDIR_SIZE);
        }
        let cdir_ofs = u64::try_from(self.buf.len()).map_err(|_| ERR_ARCHIVE_TOO_LARGE)?;
        if cdir_ofs + cdir_size + EOCD_LEN as u64 > u64::from(u32::MAX) {
            return Err(ERR_ARCHIVE_TOO_LARGE);
        }

        for e in &self.entries {
            let version = if e.method == METHOD_STORED { 0 } else { VERSION };
            self.buf.extend_from_slice(&CDH_SIG.to_le_bytes());
            self.buf.extend_from_slice(&VERSION.to_le_bytes());
            self.buf.extend_from_slice(&version.to_le_bytes());
            self.buf.extend_from_slice(&FLAG_UTF8.to_le_bytes());
            self.buf.extend_from_slice(&e.method.to_le_bytes());
            self.buf.extend_from_slice(&e.dos_time.to_le_bytes());
            self.buf.extend_from_slice(&e.dos_date.to_le_bytes());
            self.buf.extend_from_slice(&e.crc32.to_le_bytes());
            self.buf.extend_from_slice(&e.comp_size.to_le_bytes());
            self.buf.extend_from_slice(&e.uncomp_size.to_le_bytes());
            self.buf.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            self.buf.extend_from_slice(&(e.comment.len() as u16).to_le_bytes());
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            self.buf.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            self.buf.extend_from_slice(&e.external_attr.to_le_bytes());
            self.buf.extend_from_slice(&e.local_ofs.to_le_bytes());
            self.buf.extend_from_slice(&e.name);
            self.buf.extend_from_slice(&e.comment);
        }

        // End of central directory: one disk, no archive comment
        let count = self.entries.len() as u16;
        self.buf.extend_from_slice(&EOCD_SIG.to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // this disk
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // disk with the central directory
        self.buf.extend_from_slice(&count.to_le_bytes()); // entries on this disk
        self.buf.extend_from_slice(&count.to_le_bytes()); // entries in total
        self.buf.extend_from_slice(&(cdir_size as u32).to_le_bytes());
        self.buf.extend_from_slice(&(cdir_ofs as u32).to_le_bytes());
        self.buf.extend_from_slice(&0u16.to_le_bytes()); // comment length

        self.finished = true;
        Ok(std::mem::take(&mut self.buf))
    }
}
