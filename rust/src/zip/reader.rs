// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Reads a ZIP archive that is in memory, the way miniz's mz_zip_reader does.
//! The checks, their order, the error codes and the last-error state follow
//! src/zip/miniz/miniz.c: mz_zip_reader_locate_header_sig (the end record
//! search), mz_zip_reader_read_central_dir, mz_zip_file_stat_internal and
//! mz_zip_reader_extract_to_mem_no_alloc1.
//!
//! miniz quirks that are kept, because the teleporter's output depends on them:
//! - the extra-field scan of an entry reads from the start of the central
//!   directory (plus the entry's name length) when the entry's extra field runs
//!   past the copy of the directory, as miniz does;
//! - the bit-10 check reads the method and the time as one LE32, and the 0x2000
//!   flag rejects the entry;
//! - mz_zip_reader_is_file_supported() sets the last error while a stat still
//!   succeeds, and a deflated member that fails to inflate sets no error, so the
//!   last error from before is the one logged.
//!
//! Differences from miniz, which only change archives miniz reads as garbage:
//! - a member with compressed size 0 (or a directory) and a non-zero
//!   uncompressed size is UNEXPECTED_DECOMPRESSED_SIZE; miniz returns success
//!   and leaves the buffer untouched;
//! - a member whose data range runs past the end of the archive (only possible
//!   with a ZIP64 size that wraps around) is INVALID_HEADER_OR_CORRUPTED; miniz
//!   reads past the buffer;
//! - a member over 256 MiB is FILE_TOO_LARGE, checked before anything is
//!   allocated (the teleporter's cap, the same as its C check);
//! - validation inflates through a 64 KiB ring buffer, so it does not need a
//!   buffer of the declared size.

use super::crc32::{crc32, Crc32};
use super::{
    ZipStat, ERR_BUF_TOO_SMALL, ERR_CRC_CHECK_FAILED, ERR_DECOMPRESSION_FAILED,
    ERR_FAILED_FINDING_CENTRAL_DIR, ERR_FILE_READ_FAILED, ERR_FILE_TOO_LARGE,
    ERR_INVALID_HEADER_OR_CORRUPTED, ERR_INVALID_PARAMETER, ERR_NONE, ERR_NOT_AN_ARCHIVE,
    ERR_TOO_MANY_FILES, ERR_UNDEFINED, ERR_UNEXPECTED_DECOMPRESSED_SIZE, ERR_VALIDATION_FAILED,
    ERR_UNSUPPORTED_CDIR_SIZE, ERR_UNSUPPORTED_ENCRYPTION, ERR_UNSUPPORTED_FEATURE,
    ERR_UNSUPPORTED_METHOD, ERR_UNSUPPORTED_MULTIDISK,
};
use miniz_oxide::inflate::core::{
    decompress, inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF, DecompressorOxide,
};
use miniz_oxide::inflate::TINFLStatus;
use std::cell::Cell;
use std::ops::Range;

/// Members larger than this are not extracted: the teleporter's cap (256 MiB)
pub const MEMBER_LIMIT: u64 = 0x1000_0000;

/// Record signatures and sizes (ZIP APPNOTE 4.3)
pub const EOCD_SIG: u32 = 0x0605_4b50;
pub const EOCD_LEN: usize = 22;
const LOCATOR_SIG: u32 = 0x0706_4b50;
const LOCATOR_LEN: usize = 20;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_EOCD_LEN: usize = 56;
pub const CDH_SIG: u32 = 0x0201_4b50;
pub const CDH_LEN: usize = 46;
pub const LDH_SIG: u32 = 0x0403_4b50;
pub const LDH_LEN: usize = 30;

/// General purpose bit flags
pub const FLAG_ENCRYPTED: u16 = 1;
pub const FLAG_PATCH: u16 = 1 << 5;
pub const FLAG_STRONG_ENCRYPTION: u16 = 1 << 6;
pub const FLAG_MASKED_LOCAL: u16 = 1 << 13;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATED: u16 = 8;

const ZIP64_EXTRA_ID: u16 = 0x0001;
const DOS_DIRECTORY: u32 = 0x10;
const NAME_MAX: usize = 511;
const COMMENT_MAX: usize = 511;
/// The end record search goes back at most this far (MZ_UINT16_MAX + the record)
const SEARCH_LIMIT: u64 = 0xFFFF + EOCD_LEN as u64;
const SEARCH_CHUNK: u64 = 4096;

/// Why a member could not be read. None: failed without setting an error, as
/// miniz does when a deflated member does not inflate.
type Fail = Option<u32>;

/// Little-endian fields. None when the bytes are not in the slice.
fn le_bytes<const N: usize>(b: &[u8], ofs: usize) -> Option<[u8; N]> {
    b.get(ofs..ofs.checked_add(N)?)?.try_into().ok()
}

pub fn u16_at(b: &[u8], ofs: usize) -> Option<u16> {
    le_bytes(b, ofs).map(u16::from_le_bytes)
}

pub fn u32_at(b: &[u8], ofs: usize) -> Option<u32> {
    le_bytes(b, ofs).map(u32::from_le_bytes)
}

pub fn u64_at(b: &[u8], ofs: usize) -> Option<u64> {
    le_bytes(b, ofs).map(u64::from_le_bytes)
}

/// The offset of the end record, found the way mz_zip_reader_locate_header_sig
/// does: 4 KiB chunks from the end, a signature only counts with 22 bytes after
/// it, and the search stops after 64 KiB.
fn locate_eocd(data: &[u8]) -> Option<usize> {
    let size = data.len() as u64;
    let mut cur = size.saturating_sub(SEARCH_CHUNK);
    loop {
        let n = (size - cur).min(SEARCH_CHUNK) as usize;
        let base = usize::try_from(cur).ok()?;
        let chunk = data.get(base..base.checked_add(n)?)?;
        // Signatures start at 0..=n-4, the last one first
        for i in (0..n.saturating_sub(3)).rev() {
            if u32_at(chunk, i) == Some(EOCD_SIG) && size - (cur + i as u64) >= EOCD_LEN as u64 {
                return Some(base + i);
            }
        }
        if cur == 0 || size - cur >= SEARCH_LIMIT {
            return None;
        }
        // Overlap by 3 bytes, so a signature split over two chunks is found
        cur = cur.saturating_sub(SEARCH_CHUNK - 3);
    }
}

/// Where the central directory is, and the offset of each entry within it
struct Index {
    cdir: Range<usize>,
    entries: Vec<u32>,
}

/// Walks the extra fields of an entry the way miniz does. Returns the position
/// and size of the ZIP64 field's data, if there is one.
fn find_zip64_field(extra: &[u8]) -> Result<Option<(usize, usize)>, u32> {
    let mut at = 0usize;
    let mut remaining = extra.len();
    if remaining == 0 {
        return Ok(None);
    }
    loop {
        if remaining < 4 {
            return Err(ERR_INVALID_HEADER_OR_CORRUPTED);
        }
        let id = u16_at(extra, at).ok_or(ERR_INVALID_HEADER_OR_CORRUPTED)?;
        let size = usize::from(u16_at(extra, at + 2).ok_or(ERR_INVALID_HEADER_OR_CORRUPTED)?);
        if size + 4 > remaining {
            return Err(ERR_INVALID_HEADER_OR_CORRUPTED);
        }
        if id == ZIP64_EXTRA_ID {
            return Ok(Some((at + 4, size)));
        }
        at += 4 + size;
        remaining -= 4 + size;
        if remaining == 0 {
            return Ok(None);
        }
    }
}

/// Reads one 64-bit value of a ZIP64 field, advancing the position
fn take_u64(field: &[u8], off: &mut usize, remaining: &mut usize) -> Result<u64, u32> {
    if *remaining < 8 {
        return Err(ERR_INVALID_HEADER_OR_CORRUPTED);
    }
    let value = u64_at(field, *off).ok_or(ERR_INVALID_HEADER_OR_CORRUPTED)?;
    *off += 8;
    *remaining -= 8;
    Ok(value)
}

/// read_central_dir(): the end records, the central directory checks and the
/// per-entry checks, in miniz's order.
fn read_central_dir(data: &[u8]) -> Result<Index, u32> {
    let size = data.len() as u64;
    let eocd_ofs = locate_eocd(data).ok_or(ERR_FAILED_FINDING_CENTRAL_DIR)?;
    let eocd = data
        .get(eocd_ofs..eocd_ofs + EOCD_LEN)
        .ok_or(ERR_FILE_READ_FAILED)?;
    if u32_at(eocd, 0) != Some(EOCD_SIG) {
        return Err(ERR_NOT_AN_ARCHIVE);
    }

    // The ZIP64 locator sits right before the end record and points to the
    // ZIP64 end record. Both must be there for their values to be used.
    let mut zip64: Option<(&[u8], &[u8])> = None;
    if eocd_ofs as u64 >= (LOCATOR_LEN + ZIP64_EOCD_LEN) as u64 {
        if let Some(locator) = data.get(eocd_ofs - LOCATOR_LEN..eocd_ofs) {
            if u32_at(locator, 0) == Some(LOCATOR_SIG) {
                let record_ofs = u64_at(locator, 8).ok_or(ERR_INVALID_HEADER_OR_CORRUPTED)?;
                if record_ofs > size - ZIP64_EOCD_LEN as u64 {
                    return Err(ERR_NOT_AN_ARCHIVE);
                }
                let record = usize::try_from(record_ofs)
                    .ok()
                    .and_then(|o| data.get(o..o + ZIP64_EOCD_LEN));
                if let Some(record) = record {
                    if u32_at(record, 0) == Some(ZIP64_EOCD_SIG) {
                        zip64 = Some((locator, record));
                    }
                }
            }
        }
    }

    // The 16-bit end record fields, replaced by the ZIP64 ones if there are any
    let mut total_files = u32::from(u16_at(eocd, 10).ok_or(ERR_FILE_READ_FAILED)?);
    let mut entries_on_disk = u32::from(u16_at(eocd, 8).ok_or(ERR_FILE_READ_FAILED)?);
    let mut this_disk = u32::from(u16_at(eocd, 4).ok_or(ERR_FILE_READ_FAILED)?);
    let mut cdir_disk = u32::from(u16_at(eocd, 6).ok_or(ERR_FILE_READ_FAILED)?);
    let mut cdir_size = u32_at(eocd, 12).ok_or(ERR_FILE_READ_FAILED)?;
    let mut cdir_ofs = u64::from(u32_at(eocd, 16).ok_or(ERR_FILE_READ_FAILED)?);

    if let Some((locator, record)) = zip64 {
        let bad = ERR_INVALID_HEADER_OR_CORRUPTED;
        let total_disks = u32_at(locator, 16).ok_or(bad)?;
        let record_size = u64_at(record, 4).ok_or(bad)?;
        let rec_total = u64_at(record, 32).ok_or(bad)?;
        let rec_on_disk = u64_at(record, 24).ok_or(bad)?;
        let rec_cdir_size = u64_at(record, 40).ok_or(bad)?;

        if record_size < (ZIP64_EOCD_LEN - 12) as u64 {
            return Err(bad);
        }
        if total_disks != 1 {
            return Err(ERR_UNSUPPORTED_MULTIDISK);
        }
        // miniz's own limits: entry counts and the directory size fit 32 bits
        total_files = u32::try_from(rec_total).map_err(|_| ERR_TOO_MANY_FILES)?;
        entries_on_disk = u32::try_from(rec_on_disk).map_err(|_| ERR_TOO_MANY_FILES)?;
        cdir_size = u32::try_from(rec_cdir_size).map_err(|_| ERR_UNSUPPORTED_CDIR_SIZE)?;
        this_disk = u32_at(record, 16).ok_or(bad)?;
        cdir_disk = u32_at(record, 20).ok_or(bad)?;
        cdir_ofs = u64_at(record, 48).ok_or(bad)?;
    }

    if total_files != entries_on_disk {
        return Err(ERR_UNSUPPORTED_MULTIDISK);
    }
    if (this_disk | cdir_disk) != 0 && (this_disk != 1 || cdir_disk != 1) {
        return Err(ERR_UNSUPPORTED_MULTIDISK);
    }
    if u64::from(cdir_size) < u64::from(total_files) * CDH_LEN as u64 {
        return Err(ERR_INVALID_HEADER_OR_CORRUPTED);
    }
    // miniz adds without an overflow check here, so the sum may wrap
    if cdir_ofs.wrapping_add(u64::from(cdir_size)) > size {
        return Err(ERR_INVALID_HEADER_OR_CORRUPTED);
    }
    if total_files == 0 {
        return Ok(Index {
            cdir: 0..0,
            entries: Vec::new(),
        });
    }

    let cdir_len = usize::try_from(cdir_size).map_err(|_| ERR_FILE_READ_FAILED)?;
    let cdir_start = usize::try_from(cdir_ofs).map_err(|_| ERR_FILE_READ_FAILED)?;
    let cdir_end = cdir_start
        .checked_add(cdir_len)
        .ok_or(ERR_FILE_READ_FAILED)?;
    let cdir = data
        .get(cdir_start..cdir_end)
        .ok_or(ERR_FILE_READ_FAILED)?;

    // Bounded by the directory's size (each record is at least 46 bytes), not by the declared count
    let mut entries = Vec::with_capacity((total_files as usize).min(cdir.len() / CDH_LEN));
    let mut pos = 0usize;
    // m_zip64_has_extended_info_fields: once an entry has the ZIP64 field, the
    // later entries are not scanned
    let mut zip64_fields_seen = false;
    for _ in 0..total_files {
        let bad = ERR_INVALID_HEADER_OR_CORRUPTED;
        let p = cdir.get(pos..).ok_or(bad)?;
        let n = p.len();
        if n < CDH_LEN || u32_at(p, 0) != Some(CDH_SIG) {
            return Err(bad);
        }
        entries.push(u32::try_from(pos).map_err(|_| bad)?);

        let comp = u64::from(u32_at(p, 20).ok_or(bad)?);
        let decomp = u64::from(u32_at(p, 24).ok_or(bad)?);
        let local_ofs = u64::from(u32_at(p, 42).ok_or(bad)?);
        let name_len = usize::from(u16_at(p, 28).ok_or(bad)?);
        let extra_len = usize::from(u16_at(p, 30).ok_or(bad)?);

        if !zip64_fields_seen
            && extra_len != 0
            && comp.max(decomp).max(local_ofs) == 0xFFFF_FFFF
            && scan_entry_extra(data, cdir_ofs, p, name_len, extra_len)?
        {
            zip64_fields_seen = true;
        }

        if comp != 0xFFFF_FFFF && decomp != 0xFFFF_FFFF {
            // Reads the method and the time as one LE32, as miniz does
            let method_and_time = u32_at(p, 10).ok_or(bad)?;
            if (method_and_time == 0 && decomp != comp) || (decomp != 0 && comp == 0) {
                return Err(bad);
            }
        }

        let disk_start = u32::from(u16_at(p, 34).ok_or(bad)?);
        if disk_start == 0xFFFF || (disk_start != this_disk && disk_start != 1) {
            return Err(ERR_UNSUPPORTED_MULTIDISK);
        }

        if comp != 0xFFFF_FFFF && local_ofs + LDH_LEN as u64 + comp > size {
            return Err(bad);
        }

        if u16_at(p, 8).ok_or(bad)? & FLAG_MASKED_LOCAL != 0 {
            return Err(ERR_UNSUPPORTED_ENCRYPTION);
        }

        let total = CDH_LEN + name_len + extra_len + usize::from(u16_at(p, 32).ok_or(bad)?);
        if total > n {
            return Err(bad);
        }
        pos += total;
    }

    Ok(Index {
        cdir: cdir_start..cdir_end,
        entries,
    })
}

/// The extra-field scan of read_central_dir(). Like miniz, an extra field that
/// runs past the copy of the central directory is read from the archive at
/// cdir_ofs + 46 + name_len, not from the entry. Returns true if the entry has
/// a ZIP64 field.
fn scan_entry_extra(
    data: &[u8],
    cdir_ofs: u64,
    p: &[u8],
    name_len: usize,
    extra_len: usize,
) -> Result<bool, u32> {
    let bad = ERR_INVALID_HEADER_OR_CORRUPTED;
    let extra: &[u8] = if CDH_LEN + name_len + extra_len > p.len() {
        let at = cdir_ofs
            .checked_add((CDH_LEN + name_len) as u64)
            .and_then(|o| usize::try_from(o).ok())
            .ok_or(ERR_FILE_READ_FAILED)?;
        data.get(at..at.checked_add(extra_len).ok_or(ERR_FILE_READ_FAILED)?)
            .ok_or(ERR_FILE_READ_FAILED)?
    } else {
        p.get(CDH_LEN + name_len..CDH_LEN + name_len + extra_len)
            .ok_or(bad)?
    };
    Ok(find_zip64_field(extra)?.is_some())
}

/// Checks that a member can be read: encryption, patch data and the method
fn check_supported(st: &ZipStat) -> Result<(), Fail> {
    if st.bit_flag & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION | FLAG_PATCH) != 0 {
        return Err(Some(ERR_UNSUPPORTED_ENCRYPTION));
    }
    if st.method != METHOD_STORED && st.method != METHOD_DEFLATED {
        return Err(Some(ERR_UNSUPPORTED_METHOD));
    }
    Ok(())
}

/// The members, the way miniz's mz_zip_reader sees them
pub struct Reader<'a> {
    data: &'a [u8],
    index: Index,
    last_error: Cell<u32>,
}

impl<'a> Reader<'a> {
    /// mz_zip_reader_init_mem(): reads the central directory of `data`
    pub fn open(data: &'a [u8]) -> Result<Reader<'a>, u32> {
        if data.len() < EOCD_LEN {
            return Err(ERR_NOT_AN_ARCHIVE);
        }
        let index = read_central_dir(data)?;
        Ok(Reader {
            data,
            index,
            last_error: Cell::new(ERR_NONE),
        })
    }

    pub fn num_files(&self) -> u32 {
        u32::try_from(self.index.entries.len()).unwrap_or(u32::MAX)
    }

    /// Sets the last error (mz_zip_set_error())
    pub fn set_error(&self, code: u32) {
        self.last_error.set(code);
    }

    /// Returns the last error and clears it (mz_zip_get_last_error())
    pub fn take_error(&self) -> u32 {
        self.last_error.replace(ERR_NONE)
    }

    /// The central directory record of member `index` (mz_zip_get_cdh())
    fn cdh(&self, index: u32) -> Option<&'a [u8]> {
        let data: &'a [u8] = self.data;
        let ofs = *self.index.entries.get(usize::try_from(index).ok()?)?;
        let cdir: &'a [u8] = data.get(self.index.cdir.clone())?;
        cdir.get(usize::try_from(ofs).ok()?..)
    }

    /// mz_zip_reader_file_stat(). Returns None on error, with the error set.
    /// An unsupported member still gives its stat, and sets the last error.
    pub fn file_stat(&self, index: u32) -> Option<ZipStat> {
        let Some(p) = self.cdh(index) else {
            self.set_error(ERR_INVALID_PARAMETER);
            return None;
        };
        match self.stat_entry(p) {
            Ok(st) => Some(st),
            Err(code) => {
                self.set_error(code);
                None
            }
        }
    }

    /// mz_zip_file_stat_internal() for the central directory record `p`
    fn stat_entry(&self, p: &[u8]) -> Result<ZipStat, u32> {
        let bad = ERR_INVALID_HEADER_OR_CORRUPTED;
        let method = u16_at(p, 10).ok_or(bad)?;
        let bit_flag = u16_at(p, 8).ok_or(bad)?;
        let name_len = usize::from(u16_at(p, 28).ok_or(bad)?);
        let extra_len = usize::from(u16_at(p, 30).ok_or(bad)?);
        let comment_len = usize::from(u16_at(p, 32).ok_or(bad)?);
        let external_attr = u32_at(p, 38).ok_or(bad)?;

        let mut st = ZipStat::new();
        st.method = method;
        st.bit_flag = bit_flag;
        st.dos_time = u16_at(p, 12).ok_or(bad)?;
        st.dos_date = u16_at(p, 14).ok_or(bad)?;
        st.crc32 = u32_at(p, 16).ok_or(bad)?;
        st.external_attr = external_attr;
        st.comp_size = u64::from(u32_at(p, 20).ok_or(bad)?);
        st.uncomp_size = u64::from(u32_at(p, 24).ok_or(bad)?);
        st.local_header_ofs = u64::from(u32_at(p, 42).ok_or(bad)?);

        // The name and the comment, cut to 511 bytes as miniz does
        let name_n = name_len.min(NAME_MAX);
        let name = p
            .get(CDH_LEN..CDH_LEN + name_len)
            .ok_or(bad)?
            .get(..name_n)
            .ok_or(bad)?;
        st.name[..name_n].copy_from_slice(name);
        let comment_n = comment_len.min(COMMENT_MAX);
        let comment_at = CDH_LEN + name_len + extra_len;
        let comment = p
            .get(comment_at..comment_at + comment_n)
            .ok_or(bad)?;
        st.comment[..comment_n].copy_from_slice(comment);

        // mz_zip_reader_is_file_a_directory()
        st.is_directory = (name_len != 0 && p.get(CDH_LEN + name_len - 1) == Some(&b'/'))
            || external_attr & DOS_DIRECTORY != 0;

        // mz_zip_reader_is_file_supported(): sets the error and keeps the stat
        if method != METHOD_STORED && method != METHOD_DEFLATED {
            self.set_error(ERR_UNSUPPORTED_METHOD);
        } else if bit_flag & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
            self.set_error(ERR_UNSUPPORTED_ENCRYPTION);
        } else if bit_flag & FLAG_PATCH != 0 {
            self.set_error(ERR_UNSUPPORTED_FEATURE);
        }

        // ZIP64 values replace the 0xFFFFFFFF fields, found in the extra data
        if st.comp_size.max(st.uncomp_size).max(st.local_header_ofs) == 0xFFFF_FFFF {
            let extra = p
                .get(CDH_LEN + name_len..CDH_LEN + name_len + extra_len)
                .ok_or(bad)?;
            if let Some((at, size)) = find_zip64_field(extra)? {
                let field = extra.get(at..at + size).ok_or(bad)?;
                let mut off = 0usize;
                let mut remaining = size;
                if st.uncomp_size == 0xFFFF_FFFF {
                    st.uncomp_size = take_u64(field, &mut off, &mut remaining)?;
                }
                if st.comp_size == 0xFFFF_FFFF {
                    st.comp_size = take_u64(field, &mut off, &mut remaining)?;
                }
                if st.local_header_ofs == 0xFFFF_FFFF {
                    st.local_header_ofs = take_u64(field, &mut off, &mut remaining)?;
                }
            }
        }
        Ok(st)
    }

    /// mz_zip_reader_extract_to_mem(): the uncompressed data of member `index`
    /// into `out`, which must hold at least its uncompressed size. Returns false
    /// on error, with the last error set (or left as it was, see `Fail`).
    pub fn extract(&self, index: u32, out: &mut [u8]) -> bool {
        let Some(st) = self.file_stat(index) else {
            return false;
        };
        match self.extract_stat(&st, out) {
            Ok(()) => true,
            Err(fail) => {
                if let Some(code) = fail {
                    self.set_error(code);
                }
                false
            }
        }
    }

    /// mz_zip_reader_extract_to_mem_no_alloc1() for a member's stat
    fn extract_stat(&self, st: &ZipStat, out: &mut [u8]) -> Result<(), Fail> {
        // A directory or an empty member: success, but no data to write
        if st.is_directory || st.comp_size == 0 {
            return if st.uncomp_size == 0 {
                Ok(())
            } else {
                Err(Some(ERR_UNEXPECTED_DECOMPRESSED_SIZE))
            };
        }
        check_supported(st)?;
        if st.uncomp_size > MEMBER_LIMIT {
            return Err(Some(ERR_FILE_TOO_LARGE));
        }
        let uncomp = usize::try_from(st.uncomp_size).map_err(|_| Some(ERR_FILE_TOO_LARGE))?;
        let out = out.get_mut(..uncomp).ok_or(Some(ERR_BUF_TOO_SMALL))?;
        let src = self.member_data(st)?;

        if st.method == METHOD_STORED {
            out.copy_from_slice(src);
            return if crc32(out) == st.crc32 {
                Ok(())
            } else {
                Err(Some(ERR_CRC_CHECK_FAILED))
            };
        }

        let (status, produced) = inflate_into(src, out);
        if status != TINFLStatus::Done {
            // miniz sets no error for this, so the last error stays as it is
            return Err(None);
        }
        if produced != uncomp {
            return Err(Some(ERR_UNEXPECTED_DECOMPRESSED_SIZE));
        }
        if crc32(out) != st.crc32 {
            return Err(Some(ERR_CRC_CHECK_FAILED));
        }
        Ok(())
    }

    /// The member's bytes in the archive, after its local header: the
    /// uncompressed size for a stored member, the compressed size for a
    /// deflated one. The local header is checked first, as miniz does.
    fn member_data(&self, st: &ZipStat) -> Result<&'a [u8], Fail> {
        let data: &'a [u8] = self.data;
        let local_ofs = usize::try_from(st.local_header_ofs).map_err(|_| Some(ERR_FILE_READ_FAILED))?;
        let local = data
            .get(local_ofs..local_ofs.checked_add(LDH_LEN).ok_or(Some(ERR_FILE_READ_FAILED))?)
            .ok_or(Some(ERR_FILE_READ_FAILED))?;
        if u32_at(local, 0) != Some(LDH_SIG) {
            return Err(Some(ERR_INVALID_HEADER_OR_CORRUPTED));
        }
        let name_len = u64::from(u16_at(local, 26).ok_or(Some(ERR_INVALID_HEADER_OR_CORRUPTED))?);
        let extra_len = u64::from(u16_at(local, 28).ok_or(Some(ERR_INVALID_HEADER_OR_CORRUPTED))?);

        // local_ofs < data.len(), so this sum cannot overflow
        let start = st.local_header_ofs + LDH_LEN as u64 + name_len + extra_len;
        let archive_len = data.len() as u64;
        match start.checked_add(st.comp_size) {
            Some(end) if end <= archive_len => {}
            _ => return Err(Some(ERR_INVALID_HEADER_OR_CORRUPTED)),
        }
        let start = usize::try_from(start).map_err(|_| Some(ERR_INVALID_HEADER_OR_CORRUPTED))?;

        if st.method == METHOD_STORED {
            let uncomp = usize::try_from(st.uncomp_size).map_err(|_| Some(ERR_FILE_READ_FAILED))?;
            let end = start.checked_add(uncomp).ok_or(Some(ERR_FILE_READ_FAILED))?;
            data.get(start..end).ok_or(Some(ERR_FILE_READ_FAILED))
        } else {
            let comp = usize::try_from(st.comp_size).map_err(|_| Some(ERR_INVALID_HEADER_OR_CORRUPTED))?;
            let end = start.checked_add(comp).ok_or(Some(ERR_INVALID_HEADER_OR_CORRUPTED))?;
            data.get(start..end).ok_or(Some(ERR_INVALID_HEADER_OR_CORRUPTED))
        }
    }

    /// mz_zip_validate_file() for one member: the flags and method, the local
    /// header's name and bounds, and the data's size and CRC. The data is
    /// inflated through a ring, so no buffer of the declared size is needed.
    fn check_member(&self, st: &ZipStat) -> Result<(), Fail> {
        // A directory or an empty member has nothing to check, as in miniz
        if st.is_directory || st.uncomp_size == 0 {
            return Ok(());
        }
        if st.bit_flag & (FLAG_ENCRYPTED | FLAG_STRONG_ENCRYPTION) != 0 {
            return Err(Some(ERR_UNSUPPORTED_ENCRYPTION));
        }
        if st.method != METHOD_STORED && st.method != METHOD_DEFLATED {
            return Err(Some(ERR_UNSUPPORTED_METHOD));
        }
        if st.bit_flag & FLAG_PATCH != 0 {
            return Err(Some(ERR_UNSUPPORTED_FEATURE));
        }
        self.check_local_name(st)?;
        let src = self.member_data(st)?;
        if st.method == METHOD_STORED {
            return if crc32(src) == st.crc32 {
                Ok(())
            } else {
                Err(Some(ERR_CRC_CHECK_FAILED))
            };
        }
        check_deflated(src, st.uncomp_size, st.crc32)
    }

    /// The local header's name against the central one, as validation compares
    /// them: the lengths (strlen of the copied name, so an embedded NUL counts),
    /// the bounds of the data, and the name bytes.
    fn check_local_name(&self, st: &ZipStat) -> Result<(), Fail> {
        let bad = Some(ERR_INVALID_HEADER_OR_CORRUPTED);
        let local_ofs = usize::try_from(st.local_header_ofs).map_err(|_| Some(ERR_FILE_READ_FAILED))?;
        let local = self
            .data
            .get(local_ofs..local_ofs.checked_add(LDH_LEN).ok_or(Some(ERR_FILE_READ_FAILED))?)
            .ok_or(Some(ERR_FILE_READ_FAILED))?;
        if u32_at(local, 0) != Some(LDH_SIG) {
            return Err(bad);
        }
        let name_len = usize::from(u16_at(local, 26).ok_or(bad)?);
        let extra_len = u64::from(u16_at(local, 28).ok_or(bad)?);
        let central_len = st.name.iter().position(|&b| b == 0).unwrap_or(st.name.len());
        if name_len != central_len {
            return Err(bad);
        }
        let data_start = st.local_header_ofs + LDH_LEN as u64 + name_len as u64 + extra_len;
        match data_start.checked_add(st.comp_size) {
            Some(end) if end <= self.data.len() as u64 => {}
            _ => return Err(bad),
        }
        // local_ofs + LDH_LEN is in the slice, so this name range is too
        let name_at = local_ofs + LDH_LEN;
        let on_disk = self
            .data
            .get(name_at..name_at + name_len)
            .ok_or(Some(ERR_FILE_READ_FAILED))?;
        if on_disk != &st.name[..name_len] {
            return Err(Some(ERR_VALIDATION_FAILED));
        }
        Ok(())
    }
}

/// Inflates `src` into `out`, which holds the whole output. Returns the status
/// and the number of bytes written.
fn inflate_into(src: &[u8], out: &mut [u8]) -> (TINFLStatus, usize) {
    let mut inflator = Box::new(DecompressorOxide::new());
    let (status, _consumed, produced) = decompress(
        &mut inflator,
        src,
        out,
        0,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    (status, produced)
}

/// Inflates `src` through a 64 KiB ring buffer and checks the size and CRC of
/// the output. The ring is as large as the deflate window, so memory use does
/// not depend on the size the member declares.
fn check_deflated(src: &[u8], uncomp: u64, crc: u32) -> Result<(), Fail> {
    const RING: usize = 1 << 16;
    let mut inflator = Box::new(DecompressorOxide::new());
    let mut ring = vec![0u8; RING];
    let mut ring_pos = 0usize;
    let mut in_pos = 0usize;
    let mut produced_total = 0u64;
    let mut hasher = Crc32::default();
    loop {
        let input = src.get(in_pos..).ok_or(None)?;
        let (status, used_in, used_out) =
            decompress(&mut inflator, input, &mut ring, ring_pos, 0);
        if used_out > RING {
            return Err(None);
        }
        // The bytes this call wrote start at ring_pos and may wrap around
        let first = used_out.min(RING - ring_pos);
        hasher.update(ring.get(ring_pos..ring_pos + first).ok_or(None)?);
        hasher.update(ring.get(..used_out - first).ok_or(None)?);
        produced_total += used_out as u64;
        if produced_total > uncomp {
            return Err(Some(ERR_UNEXPECTED_DECOMPRESSED_SIZE));
        }
        in_pos += used_in;
        ring_pos = (ring_pos + used_out) % RING;
        match status {
            TINFLStatus::Done => break,
            TINFLStatus::HasMoreOutput => {}
            _ => return Err(None),
        }
        if used_in == 0 && used_out == 0 {
            return Err(None);
        }
    }
    if produced_total != uncomp {
        return Err(Some(ERR_UNEXPECTED_DECOMPRESSED_SIZE));
    }
    if hasher.finish() != crc {
        return Err(Some(ERR_CRC_CHECK_FAILED));
    }
    Ok(())
}

/// mz_zip_validate_mem_archive() without the locate check: every member's
/// stat, and its data checked as extraction checks it. Returns 0 if the archive
/// is valid, otherwise the error.
pub fn validate(data: &[u8]) -> u32 {
    if data.is_empty() {
        return ERR_INVALID_PARAMETER;
    }
    let reader = match Reader::open(data) {
        Ok(reader) => reader,
        Err(code) => return code,
    };
    for index in 0..reader.num_files() {
        let Some(st) = reader.file_stat(index) else {
            return match reader.take_error() {
                ERR_NONE => ERR_UNDEFINED,
                code => code,
            };
        };
        if let Err(fail) = reader.check_member(&st) {
            return fail.unwrap_or(ERR_DECOMPRESSION_FAILED);
        }
    }
    ERR_NONE
}
