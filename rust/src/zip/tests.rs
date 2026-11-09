// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Tests of the zip module: round trips, the reader's checks (each miniz rule the
//! teleporter can reach), the last-error state, the writer's rules, the FFI NULL
//! rules, and a deterministic mutation pass that must never panic.

use super::crc32::crc32;
use super::reader::{
    validate, Reader, CDH_SIG, EOCD_LEN, EOCD_SIG, FLAG_ENCRYPTED, FLAG_MASKED_LOCAL, FLAG_PATCH,
    LDH_SIG, MEMBER_LIMIT, METHOD_DEFLATED, METHOD_STORED,
};
use super::writer::Writer;
use super::{
    ftl_rs_zip_extract, ftl_rs_zip_file_stat, ftl_rs_zip_last_error, ftl_rs_zip_num_files,
    ftl_rs_zip_open, ftl_rs_zip_reader_free, ftl_rs_zip_validate, ftl_rs_zip_writer_add,
    ftl_rs_zip_writer_free, ftl_rs_zip_writer_new, ZipReader, ZipStat, ZipWriter,
    ERR_BUF_TOO_SMALL, ERR_CRC_CHECK_FAILED, ERR_DECOMPRESSION_FAILED,
    ERR_FAILED_FINDING_CENTRAL_DIR, ERR_FILE_TOO_LARGE,
    ERR_INVALID_FILENAME, ERR_INVALID_HEADER_OR_CORRUPTED, ERR_INVALID_PARAMETER, ERR_NONE,
    ERR_NOT_AN_ARCHIVE, ERR_TOO_MANY_FILES, ERR_UNEXPECTED_DECOMPRESSED_SIZE,
    ERR_UNSUPPORTED_ENCRYPTION, ERR_UNSUPPORTED_FEATURE, ERR_UNSUPPORTED_METHOD,
    ERR_UNSUPPORTED_MULTIDISK, ERR_VALIDATION_FAILED,
};
use miniz_oxide::deflate::compress_to_vec;
use miniz_oxide::inflate::core::{
    decompress, inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF, DecompressorOxide,
};
use miniz_oxide::inflate::TINFLStatus;
use std::ptr;

const DOS_TIME: u16 = 0x6000;
const DOS_DATE: u16 = 0x5A21;
const ZIP64_EOCD_SIG: u32 = 0x0606_4B50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4B50;

/// Bytes that compress well (a repeating pattern)
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

/// Bytes that do not compress (xorshift)
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// The bytes of a NUL-terminated field of a ZipStat
fn cstr(field: &[u8; 512]) -> &[u8] {
    let n = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    &field[..n]
}

/// Writes the members with the writer, as the teleporter does
fn write_archive(members: Vec<(&str, Vec<u8>, &str)>) -> Vec<u8> {
    let mut w = Writer::new();
    for (name, data, comment) in members {
        w.add(name.as_bytes(), &data, comment.as_bytes(), DOS_TIME, DOS_DATE)
            .expect("add");
    }
    w.finish().expect("finish")
}

/// A member written by hand, so that a test can make it inconsistent
#[derive(Clone)]
struct Raw {
    name: Vec<u8>,
    method: u16,
    flags: u16,
    disk: u16,
    /// The bytes after the local header
    comp: Vec<u8>,
    /// The sizes and CRC in both headers
    comp_size: u32,
    uncomp_size: u32,
    crc: u32,
    external_attr: u32,
    /// The central directory's extra field
    extra: Vec<u8>,
    comment: Vec<u8>,
    /// The local header's name, when it differs from `name`
    local_name: Option<Vec<u8>>,
}

impl Raw {
    fn stored(name: &[u8], data: &[u8]) -> Raw {
        Raw {
            name: name.to_vec(),
            method: METHOD_STORED,
            flags: 0,
            disk: 0,
            comp: data.to_vec(),
            comp_size: data.len() as u32,
            uncomp_size: data.len() as u32,
            crc: crc32(data),
            external_attr: 0,
            extra: Vec::new(),
            comment: Vec::new(),
            local_name: None,
        }
    }

    fn deflated(name: &[u8], data: &[u8]) -> Raw {
        let comp = compress_to_vec(data, 6);
        let mut raw = Raw::stored(name, data);
        raw.method = METHOD_DEFLATED;
        raw.comp_size = comp.len() as u32;
        raw.comp = comp;
        raw
    }
}

/// The end record. The counts and sizes are written as given.
struct End {
    disk: u16,
    cdir_disk: u16,
    on_disk: u16,
    total: u16,
    cdir_size: u32,
    cdir_ofs: u32,
    comment: Vec<u8>,
}

fn push_end(out: &mut Vec<u8>, end: &End) {
    out.extend_from_slice(&EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&end.disk.to_le_bytes());
    out.extend_from_slice(&end.cdir_disk.to_le_bytes());
    out.extend_from_slice(&end.on_disk.to_le_bytes());
    out.extend_from_slice(&end.total.to_le_bytes());
    out.extend_from_slice(&end.cdir_size.to_le_bytes());
    out.extend_from_slice(&end.cdir_ofs.to_le_bytes());
    out.extend_from_slice(&(end.comment.len() as u16).to_le_bytes());
    out.extend_from_slice(&end.comment);
}

/// The local records and central records of the members, without an end
/// record. Returns the bytes, and the central directory's offset and size.
fn body(members: &[Raw]) -> (Vec<u8>, u32, u32) {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for m in members {
        offsets.push(out.len() as u32);
        let local_name: &[u8] = m.local_name.as_deref().unwrap_or(&m.name[..]);
        out.extend_from_slice(&LDH_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&m.flags.to_le_bytes());
        out.extend_from_slice(&m.method.to_le_bytes());
        out.extend_from_slice(&DOS_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&m.crc.to_le_bytes());
        out.extend_from_slice(&m.comp_size.to_le_bytes());
        out.extend_from_slice(&m.uncomp_size.to_le_bytes());
        out.extend_from_slice(&(local_name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(local_name);
        out.extend_from_slice(&m.comp);
    }
    let cdir_ofs = out.len() as u32;
    for (m, ofs) in members.iter().zip(offsets) {
        out.extend_from_slice(&CDH_SIG.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&m.flags.to_le_bytes());
        out.extend_from_slice(&m.method.to_le_bytes());
        out.extend_from_slice(&DOS_TIME.to_le_bytes());
        out.extend_from_slice(&DOS_DATE.to_le_bytes());
        out.extend_from_slice(&m.crc.to_le_bytes());
        out.extend_from_slice(&m.comp_size.to_le_bytes());
        out.extend_from_slice(&m.uncomp_size.to_le_bytes());
        out.extend_from_slice(&(m.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(m.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&(m.comment.len() as u16).to_le_bytes());
        out.extend_from_slice(&m.disk.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&m.external_attr.to_le_bytes());
        out.extend_from_slice(&ofs.to_le_bytes());
        out.extend_from_slice(&m.name);
        out.extend_from_slice(&m.extra);
        out.extend_from_slice(&m.comment);
    }
    let cdir_size = out.len() as u32 - cdir_ofs;
    (out, cdir_ofs, cdir_size)
}

/// An archive of the members with a correct end record
fn raw(members: &[Raw]) -> Vec<u8> {
    let (mut out, cdir_ofs, cdir_size) = body(members);
    let n = members.len() as u16;
    push_end(
        &mut out,
        &End {
            disk: 0,
            cdir_disk: 0,
            on_disk: n,
            total: n,
            cdir_size,
            cdir_ofs,
            comment: Vec::new(),
        },
    );
    out
}

/// An archive with a ZIP64 end record of `record_size` (its size field) and a
/// locator. The 32-bit end record holds placeholders.
fn zip64(members: &[Raw], record_size: u64) -> Vec<u8> {
    let (mut out, cdir_ofs, cdir_size) = body(members);
    let rec_ofs = out.len() as u64;
    let n = members.len() as u64;
    out.extend_from_slice(&ZIP64_EOCD_SIG.to_le_bytes());
    out.extend_from_slice(&record_size.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&45u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(&u64::from(cdir_size).to_le_bytes());
    out.extend_from_slice(&u64::from(cdir_ofs).to_le_bytes());
    out.extend_from_slice(&ZIP64_LOCATOR_SIG.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&rec_ofs.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    push_end(
        &mut out,
        &End {
            disk: 0,
            cdir_disk: 0,
            on_disk: 0xFFFF,
            total: 0xFFFF,
            cdir_size: 0xFFFF_FFFF,
            cdir_ofs: 0xFFFF_FFFF,
            comment: Vec::new(),
        },
    );
    out
}

/// A ZIP64 extra field holding the 64-bit values
fn zip64_extra(values: &[u64]) -> Vec<u8> {
    let mut field = Vec::new();
    field.extend_from_slice(&1u16.to_le_bytes());
    field.extend_from_slice(&((values.len() * 8) as u16).to_le_bytes());
    for value in values {
        field.extend_from_slice(&value.to_le_bytes());
    }
    field
}

/// Reads every member the way the teleporter does, and leaves no panic behind
fn exercise(data: &[u8]) {
    let _ = validate(data);
    let Ok(reader) = Reader::open(data) else {
        return;
    };
    for i in 0..reader.num_files() {
        if let Some(st) = reader.file_stat(i) {
            if st.uncomp_size <= 64 * 1024 {
                let mut out = vec![0u8; st.uncomp_size as usize];
                let _ = reader.extract(i, &mut out);
            }
        }
        let _ = reader.take_error();
    }
}

/// xorshift64, fixed seed: the mutations are the same on every run
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    for (i, byte) in bytes.iter().enumerate() {
        if let Some(slot) = buf.get_mut(at + i) {
            *slot = *byte;
        }
    }
}

/// One mutation: a bit flip, a byte, a size field (0, max, 0x80000000 or random),
/// a truncation, or a buffer of random bytes
fn mutate(rng: &mut Rng, buf: &mut Vec<u8>) {
    let kind = rng.below(6);
    if buf.is_empty() {
        buf.push(rng.next_u64() as u8);
        return;
    }
    let at = rng.below(buf.len());
    match kind {
        0 => buf[at] ^= 1 << rng.below(8),
        1 => buf[at] = rng.next_u64() as u8,
        2 => {
            let values = [0u32, u32::MAX, 0x8000_0000, rng.next_u64() as u32];
            let value = values[rng.below(values.len())];
            put(buf, at, &value.to_le_bytes());
        }
        3 => {
            let values = [0u16, u16::MAX, rng.next_u64() as u16];
            let value = values[rng.below(values.len())];
            put(buf, at, &value.to_le_bytes());
        }
        4 => buf.truncate(at),
        _ => {
            let n = rng.below(300);
            *buf = (0..n).map(|_| rng.next_u64() as u8).collect();
        }
    }
}

#[test]
fn crc_of_the_check_value() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn round_trip_keeps_names_comments_sizes_and_data() {
    let sizes = [0usize, 1, 3, 4, 100, 4096, 65536, (1 << 20) + 1];
    let datas: Vec<Vec<u8>> = sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| {
            if i % 2 == 0 {
                pattern(n)
            } else {
                noise(n, i as u64 + 1)
            }
        })
        .collect();
    let names: Vec<String> = (0..sizes.len())
        .map(|i| format!("etc/pihole/file{i}.bin"))
        .collect();
    let comments: Vec<String> = (0..sizes.len()).map(|i| format!("comment {i}")).collect();
    let members: Vec<(&str, Vec<u8>, &str)> = (0..sizes.len())
        .map(|i| (names[i].as_str(), datas[i].clone(), comments[i].as_str()))
        .collect();
    let bytes = write_archive(members);

    assert_eq!(validate(&bytes), ERR_NONE);
    let r = Reader::open(&bytes).expect("open");
    assert_eq!(r.num_files() as usize, sizes.len());
    for i in 0..sizes.len() {
        let st = r.file_stat(i as u32).expect("stat");
        assert_eq!(cstr(&st.name), names[i].as_bytes());
        assert_eq!(cstr(&st.comment), comments[i].as_bytes());
        let method = if sizes[i] <= 3 {
            METHOD_STORED
        } else {
            METHOD_DEFLATED
        };
        assert_eq!(st.method, method, "method of {i}");
        assert_eq!(st.crc32, crc32(&datas[i]));
        assert_eq!(st.uncomp_size, sizes[i] as u64);
        assert_eq!((st.dos_time, st.dos_date), (DOS_TIME, DOS_DATE));
        assert_eq!(st.bit_flag, 0x0800);
        assert!(!st.is_directory);
        let mut out = vec![0u8; sizes[i]];
        assert!(r.extract(i as u32, &mut out), "extract {i}");
        assert_eq!(out, datas[i], "data of {i}");
    }
    assert_eq!(r.take_error(), ERR_NONE);
}

#[test]
fn empty_archive_is_valid_with_no_members() {
    let bytes = Writer::new().finish().expect("finish");
    assert_eq!(bytes.len(), EOCD_LEN);
    assert_eq!(validate(&bytes), ERR_NONE);
    assert_eq!(Reader::open(&bytes).expect("open").num_files(), 0);
}

#[test]
fn writer_refuses_what_miniz_refuses() {
    let mut w = Writer::new();
    assert_eq!(w.add(b"/abs", b"x", b"", 0, 0), Err(ERR_INVALID_FILENAME));
    assert_eq!(
        w.add(&[b'n'; 65536], b"", b"", 0, 0),
        Err(ERR_INVALID_FILENAME)
    );
    assert_eq!(
        w.add(b"a", b"x", &[b'c'; 65536], 0, 0),
        Err(ERR_INVALID_PARAMETER)
    );
    // A directory carries no data
    assert_eq!(w.add(b"dir/", b"x", b"", 0, 0), Err(ERR_INVALID_PARAMETER));
    // Refused members leave the archive empty, and it can still be finished once
    let bytes = w.finish().expect("finish");
    assert_eq!(bytes.len(), EOCD_LEN);
    assert_eq!(w.finish(), Err(ERR_INVALID_PARAMETER));
    assert_eq!(w.add(b"a", b"", b"", 0, 0), Err(ERR_INVALID_PARAMETER));
}

#[test]
fn writer_refuses_more_than_65535_members_at_finish() {
    let mut w = Writer::new();
    for _ in 0..=0xFFFF {
        w.add(b"x", b"", b"", 0, 0).expect("add");
    }
    assert_eq!(w.finish(), Err(ERR_TOO_MANY_FILES));
}

#[test]
fn directories_are_directories_without_data() {
    let bytes = write_archive(vec![("etc/pihole/", Vec::new(), "")]);
    let r = Reader::open(&bytes).expect("open");
    let st = r.file_stat(0).expect("stat");
    assert!(st.is_directory);
    assert_eq!(st.comp_size, 0);
    assert!(r.extract(0, &mut []));

    // A directory by the DOS attribute alone
    let mut m = Raw::stored(b"plain", b"");
    m.external_attr = 0x10;
    let bytes = raw(&[m]);
    assert!(Reader::open(&bytes)
        .expect("open")
        .file_stat(0)
        .expect("stat")
        .is_directory);
}

#[test]
fn long_names_and_comments_are_cut_to_511_bytes() {
    let name = vec![b'n'; 600];
    let mut m = Raw::stored(&name, b"abc");
    m.comment = vec![b'c'; 600];
    let archive_bytes = raw(&[m]);
    let r = Reader::open(&archive_bytes).expect("open");
    let st = r.file_stat(0).expect("stat");
    assert_eq!(cstr(&st.name), &name[..511]);
    assert_eq!(st.name[511], 0);
    assert_eq!(cstr(&st.comment), &[b'c'; 511][..]);
    assert_eq!(st.comment[511], 0);
    let mut out = [0u8; 3];
    assert!(r.extract(0, &mut out));
    assert_eq!(&out, b"abc");
}

#[test]
fn embedded_nul_in_a_name_is_copied_raw() {
    let archive_bytes = raw(&[Raw::stored(b"a\0b", b"x")]);
    let r = Reader::open(&archive_bytes).expect("open");
    let st = r.file_stat(0).expect("stat");
    assert_eq!(&st.name[..4], b"a\0b\0");
    assert_eq!(cstr(&st.name), b"a");
}

#[test]
fn encrypted_and_unsupported_methods_stat_but_fail_extraction() {
    let mut enc = Raw::stored(b"secret", b"abc");
    enc.flags = FLAG_ENCRYPTED;
    let mut m12 = Raw::stored(b"bz", b"abc");
    m12.method = 12;
    let archive_bytes = raw(&[enc, m12]);
    let r = Reader::open(&archive_bytes).expect("open");

    // The stat succeeds and records the reason as the last error, which a read clears
    let st = r.file_stat(0).expect("stat");
    assert_eq!(st.bit_flag, FLAG_ENCRYPTED);
    assert_eq!(r.take_error(), ERR_UNSUPPORTED_ENCRYPTION);
    assert_eq!(r.take_error(), ERR_NONE);

    let mut out = [0u8; 3];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_UNSUPPORTED_ENCRYPTION);
    assert!(!r.extract(1, &mut out));
    assert_eq!(r.take_error(), ERR_UNSUPPORTED_METHOD);
}

#[test]
fn patch_flag_is_a_feature_on_stat_and_encryption_on_extract() {
    let mut m = Raw::stored(b"p", b"abc");
    m.flags = FLAG_PATCH;
    let archive_bytes = raw(&[m]);
    let r = Reader::open(&archive_bytes).expect("open");
    assert!(r.file_stat(0).is_some());
    assert_eq!(r.take_error(), ERR_UNSUPPORTED_FEATURE);
    let mut out = [0u8; 3];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_UNSUPPORTED_ENCRYPTION);
}

#[test]
fn masked_local_header_flag_refuses_the_archive() {
    let mut m = Raw::stored(b"a", b"abc");
    m.flags = FLAG_MASKED_LOCAL;
    assert_eq!(
        Reader::open(&raw(&[m])).err(),
        Some(ERR_UNSUPPORTED_ENCRYPTION)
    );
}

#[test]
fn disk_numbers_other_than_one_refuse_the_archive() {
    let mut m = Raw::stored(b"a", b"abc");
    m.disk = 0xFFFF;
    assert_eq!(
        Reader::open(&raw(&[m])).err(),
        Some(ERR_UNSUPPORTED_MULTIDISK)
    );
    let mut m = Raw::stored(b"a", b"abc");
    m.disk = 2;
    assert_eq!(
        Reader::open(&raw(&[m])).err(),
        Some(ERR_UNSUPPORTED_MULTIDISK)
    );
}

#[test]
fn end_record_checks_refuse_the_archive_with_miniz_codes() {
    let (base, cdir_ofs, cdir_size) = body(&[Raw::stored(b"a", b"abc")]);
    let open_with = |base: &[u8], end: End| {
        let mut out = base.to_vec();
        push_end(&mut out, &end);
        Reader::open(&out).err()
    };
    let end = |disk, cdir_disk, on_disk, total, cdir_size, cdir_ofs| End {
        disk,
        cdir_disk,
        on_disk,
        total,
        cdir_size,
        cdir_ofs,
        comment: Vec::new(),
    };
    // Entries on this disk differ from the total
    assert_eq!(
        open_with(&base[..], end(0, 0, 1, 2, cdir_size, cdir_ofs)),
        Some(ERR_UNSUPPORTED_MULTIDISK)
    );
    // This disk or the central directory's disk is not 0 or 1
    assert_eq!(
        open_with(&base[..], end(1, 0, 1, 1, cdir_size, cdir_ofs)),
        Some(ERR_UNSUPPORTED_MULTIDISK)
    );
    assert_eq!(
        open_with(&base[..], end(2, 2, 1, 1, cdir_size, cdir_ofs)),
        Some(ERR_UNSUPPORTED_MULTIDISK)
    );
    // Too small for one record per entry
    assert_eq!(
        open_with(&base[..], end(0, 0, 1, 1, 45, cdir_ofs)),
        Some(ERR_INVALID_HEADER_OR_CORRUPTED)
    );
    // The directory runs past the end of the archive
    assert_eq!(
        open_with(&base[..], end(0, 0, 1, 1, cdir_size, 0xFFFF_0000)),
        Some(ERR_INVALID_HEADER_OR_CORRUPTED)
    );
    // No end record at all
    assert_eq!(
        Reader::open(&[0u8; 30]).err(),
        Some(ERR_FAILED_FINDING_CENTRAL_DIR)
    );
    assert_eq!(Reader::open(&[0u8; 10]).err(), Some(ERR_NOT_AN_ARCHIVE));
    // The correct end record still opens the archive
    assert!(open_with(&base[..], end(0, 0, 1, 1, cdir_size, cdir_ofs)).is_none());
}

#[test]
fn end_record_is_found_past_a_fake_signature_in_its_comment() {
    let (mut out, cdir_ofs, cdir_size) = body(&[Raw::stored(b"a", b"abc")]);
    // A signature with fewer than 22 bytes after it does not count
    let mut comment = EOCD_SIG.to_le_bytes().to_vec();
    comment.extend_from_slice(&[0u8; 6]);
    push_end(
        &mut out,
        &End {
            disk: 0,
            cdir_disk: 0,
            on_disk: 1,
            total: 1,
            cdir_size,
            cdir_ofs,
            comment,
        },
    );
    assert_eq!(Reader::open(&out).expect("open").num_files(), 1);
}

#[test]
fn end_record_search_reaches_60_kib_from_the_end_but_not_70_kib() {
    let m = Raw::stored(b"a", b"abc");
    let mut near = raw(&[m.clone()]);
    near.extend(vec![0u8; 60_000]);
    assert_eq!(Reader::open(&near).expect("open").num_files(), 1);
    let mut far = raw(&[m]);
    far.extend(vec![0u8; 70_000]);
    assert_eq!(
        Reader::open(&far).err(),
        Some(ERR_FAILED_FINDING_CENTRAL_DIR)
    );
}

#[test]
fn zip64_end_record_is_read_when_the_locator_is_present() {
    let m = Raw::stored(b"a", b"abc");
    let bytes = zip64(&[m.clone()], 44);
    let r = Reader::open(&bytes).expect("open");
    assert_eq!(r.num_files(), 1);
    let mut out = [0u8; 3];
    assert!(r.extract(0, &mut out));
    assert_eq!(&out, b"abc");
    // A record shorter than its fixed fields is refused
    assert_eq!(
        Reader::open(&zip64(&[m], 40)).err(),
        Some(ERR_INVALID_HEADER_OR_CORRUPTED)
    );
}

#[test]
fn zip64_extra_field_supplies_the_real_sizes() {
    let data = b"hello";
    let mut m = Raw::stored(b"z64", data);
    m.uncomp_size = 0xFFFF_FFFF;
    m.extra = zip64_extra(&[5]);
    let bytes = raw(&[m]);
    let r = Reader::open(&bytes).expect("open");
    let st = r.file_stat(0).expect("stat");
    assert_eq!((st.comp_size, st.uncomp_size, st.local_header_ofs), (5, 5, 0));
    let mut out = [0u8; 5];
    assert!(r.extract(0, &mut out));
    assert_eq!(&out, data);
    assert_eq!(validate(&bytes), ERR_NONE);
}

#[test]
fn short_zip64_extra_field_fails_the_stat() {
    let mut m = Raw::stored(b"z", b"abc");
    m.uncomp_size = 0xFFFF_FFFF;
    m.extra = zip64_extra(&[]);
    let bytes = raw(&[m]);
    let r = Reader::open(&bytes).expect("open");
    assert!(r.file_stat(0).is_none());
    assert_eq!(r.take_error(), ERR_INVALID_HEADER_OR_CORRUPTED);
    assert_eq!(validate(&bytes), ERR_INVALID_HEADER_OR_CORRUPTED);
}

#[test]
fn zero_compressed_size_with_data_fails_extraction_as_documented() {
    // A zero compressed size with data to write: miniz returns success without
    // writing, and this module reports UNEXPECTED_DECOMPRESSED_SIZE instead. The
    // sizes are ZIP64 here; a zero from corruption behaves the same way.
    let mut m = Raw::stored(b"z", b"");
    m.comp = Vec::new();
    m.comp_size = 0xFFFF_FFFF;
    m.uncomp_size = 0xFFFF_FFFF;
    m.extra = zip64_extra(&[5, 0]);
    let archive_bytes = raw(&[m]);
    let r = Reader::open(&archive_bytes).expect("open");
    let st = r.file_stat(0).expect("stat");
    assert_eq!((st.comp_size, st.uncomp_size), (0, 5));
    let mut out = [0u8; 5];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_UNEXPECTED_DECOMPRESSED_SIZE);
}

#[test]
fn bad_local_header_signature_fails_extraction_and_validation() {
    let mut bytes = raw(&[Raw::stored(b"a", b"abc")]);
    bytes[0] ^= 0xFF;
    let r = Reader::open(&bytes).expect("open");
    let mut out = [0u8; 3];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_INVALID_HEADER_OR_CORRUPTED);
    assert_eq!(validate(&bytes), ERR_INVALID_HEADER_OR_CORRUPTED);
}

#[test]
fn validation_compares_local_names_but_extraction_does_not() {
    let mut m = Raw::stored(b"abc", b"xyz");
    m.local_name = Some(b"abd".to_vec());
    let bytes = raw(&[m]);
    assert_eq!(validate(&bytes), ERR_VALIDATION_FAILED);
    let r = Reader::open(&bytes).expect("open");
    let mut out = [0u8; 3];
    assert!(r.extract(0, &mut out));
    assert_eq!(&out, b"xyz");
}

#[test]
fn crc_mismatch_fails_for_stored_and_deflated_members() {
    let mut stored = Raw::stored(b"s", b"abc");
    stored.crc ^= 1;
    let mut deflated = Raw::deflated(b"d", &pattern(100));
    deflated.crc ^= 1;
    let bytes = raw(&[stored, deflated]);
    let r = Reader::open(&bytes).expect("open");
    let mut out = [0u8; 3];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_CRC_CHECK_FAILED);
    let mut out = vec![0u8; 100];
    assert!(!r.extract(1, &mut out));
    assert_eq!(r.take_error(), ERR_CRC_CHECK_FAILED);
    assert_eq!(validate(&bytes), ERR_CRC_CHECK_FAILED);
}

#[test]
fn deflate_size_mismatches_are_reported() {
    // Stream holds 10 bytes, the header says 20: short output
    let mut short = Raw::deflated(b"s", &pattern(10));
    short.uncomp_size = 20;
    let bytes = raw(&[short]);
    let r = Reader::open(&bytes).expect("open");
    let mut out = [0u8; 20];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_UNEXPECTED_DECOMPRESSED_SIZE);
    assert_eq!(validate(&bytes), ERR_UNEXPECTED_DECOMPRESSED_SIZE);

    // Stream holds 10 bytes, the header says 5: more output than declared
    let mut long = Raw::deflated(b"l", &pattern(10));
    long.uncomp_size = 5;
    let bytes = raw(&[long]);
    assert_eq!(validate(&bytes), ERR_UNEXPECTED_DECOMPRESSED_SIZE);
    let r = Reader::open(&bytes).expect("open");
    let mut out = [0u8; 5];
    assert!(!r.extract(0, &mut out));
}

#[test]
fn directory_with_data_fails_extraction_as_documented() {
    // miniz returns success and leaves the buffer untouched for a directory, by the
    // DOS attribute or by the trailing '/'. The data is corrupt, so this module keeps
    // UNEXPECTED_DECOMPRESSED_SIZE, and the caller's buffer is not written.
    for (name, attr) in [(&b"dir"[..], 0x10u32), (&b"dir/"[..], 0u32)] {
        let mut m = Raw::stored(name, b"abcd");
        m.external_attr = attr;
        let archive_bytes = raw(&[m]);
        let r = Reader::open(&archive_bytes).expect("open");
        assert!(r.file_stat(0).expect("stat").is_directory);
        let mut out = [0xA5u8; 4];
        assert!(!r.extract(0, &mut out));
        assert_eq!(r.take_error(), ERR_UNEXPECTED_DECOMPRESSED_SIZE);
        assert_eq!(out, [0xA5u8; 4]);
    }
}

#[test]
fn failed_inflate_after_stored_data_keeps_the_decoded_prefix() {
    // A stored block copies its data before the next block header, which has the
    // reserved type 3 and fails. The bytes before the failure are the decoded prefix,
    // and miniz sets no error here either. Past the prefix nothing is defined.
    let data = b"0123456789";
    let mut comp = vec![0x00, 10, 0, 0xF5, 0xFF];
    comp.extend_from_slice(data);
    comp.push(0x06);
    let mut m = Raw::stored(b"s", b"");
    m.method = METHOD_DEFLATED;
    m.comp_size = comp.len() as u32;
    m.uncomp_size = 20;
    m.comp = comp;
    let archive_bytes = raw(&[m]);
    let r = Reader::open(&archive_bytes).expect("open");
    let mut out = [0xA5u8; 20];
    assert!(!r.extract(0, &mut out));
    assert_eq!(r.take_error(), ERR_NONE);
    assert_eq!(&out[..10], &data[..]);
}

#[test]
fn failed_inflate_keeps_the_previous_last_error() {
    // miniz sets no error when inflate fails, so the error from before is logged
    let mut enc = Raw::stored(b"e", b"abc");
    enc.flags = FLAG_ENCRYPTED;
    let mut garbage = Raw::stored(b"g", b"");
    garbage.method = METHOD_DEFLATED;
    garbage.comp = vec![0xFF; 10];
    garbage.comp_size = 10;
    garbage.uncomp_size = 20;
    let bytes = raw(&[enc, garbage.clone()]);
    let r = Reader::open(&bytes).expect("open");
    assert!(r.file_stat(0).is_some());
    let mut out = [0u8; 20];
    assert!(!r.extract(1, &mut out));
    assert_eq!(r.take_error(), ERR_UNSUPPORTED_ENCRYPTION);
    // Validation stops at the first failing member, which here is the encrypted one
    assert_eq!(validate(&bytes), ERR_UNSUPPORTED_ENCRYPTION);
    // On its own, the garbage member fails validation as a decompression failure
    assert_eq!(validate(&raw(&[garbage])), ERR_DECOMPRESSION_FAILED);
}

#[test]
fn size_limits_are_checked_before_the_local_header() {
    let mut big = Raw::stored(b"big", b"abc");
    big.uncomp_size = (MEMBER_LIMIT + 1) as u32;
    let mut at = Raw::stored(b"at", b"abc");
    at.uncomp_size = MEMBER_LIMIT as u32;
    let archive_bytes = raw(&[big, at]);
    let r = Reader::open(&archive_bytes).expect("open");
    let mut small = [0u8; 16];
    assert!(!r.extract(0, &mut small));
    assert_eq!(r.take_error(), ERR_FILE_TOO_LARGE);
    assert!(!r.extract(1, &mut small));
    assert_eq!(r.take_error(), ERR_BUF_TOO_SMALL);

    let archive_bytes = raw(&[Raw::stored(b"n", b"abcd")]);

    let r = Reader::open(&archive_bytes).expect("open");
    let mut three = [0u8; 3];
    assert!(!r.extract(0, &mut three));
    assert_eq!(r.take_error(), ERR_BUF_TOO_SMALL);
}

#[test]
fn bad_indexes_set_invalid_parameter() {
    let archive_bytes = raw(&[Raw::stored(b"a", b"abc")]);
    let r = Reader::open(&archive_bytes).expect("open");
    assert!(r.file_stat(1).is_none());
    assert_eq!(r.take_error(), ERR_INVALID_PARAMETER);
    let mut out = [0u8; 3];
    assert!(!r.extract(7, &mut out));
    assert_eq!(r.take_error(), ERR_INVALID_PARAMETER);
}

#[test]
fn inflate_into_an_empty_buffer_does_not_panic() {
    let mut out: [u8; 0] = [];
    // An empty final block produces no output and finishes
    let mut inflator = Box::new(DecompressorOxide::new());
    let (status, _, _) = decompress(
        &mut inflator,
        &[3, 0],
        &mut out,
        0,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    assert!(matches!(status, TINFLStatus::Done));
    // A stream with output has nowhere to put it
    let stream = compress_to_vec(b"x", 6);
    let mut inflator = Box::new(DecompressorOxide::new());
    let (status, _, _) = decompress(
        &mut inflator,
        &stream,
        &mut out,
        0,
        TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    assert!(!matches!(status, TINFLStatus::Done));
    // The wrapping mode with an empty buffer is also safe
    let mut inflator = Box::new(DecompressorOxide::new());
    let _ = decompress(&mut inflator, &stream, &mut out, 0, 0);
}

#[test]
fn validate_of_a_large_deflated_member_uses_a_ring() {
    let big = pattern((1 << 20) + 1);
    let bytes = write_archive(vec![("big.bin", big.clone(), "")]);
    assert_eq!(validate(&bytes), ERR_NONE);
    let r = Reader::open(&bytes).expect("open");
    let mut out = vec![0u8; big.len()];
    assert!(r.extract(0, &mut out));
    assert_eq!(out, big);
}

#[test]
fn validate_of_empty_and_missing_archives() {
    assert_eq!(validate(&[]), ERR_INVALID_PARAMETER);
    assert_eq!(validate(&[0u8; 30]), ERR_FAILED_FINDING_CENTRAL_DIR);
}

#[test]
fn ffi_rejects_null_and_bad_arguments() {
    // SAFETY: every pointer passed is NULL or points to live local data
    unsafe {
        let mut reader: *mut ZipReader = ptr::null_mut();
        assert_eq!(
            ftl_rs_zip_open(ptr::null(), 10, &mut reader),
            ERR_INVALID_PARAMETER
        );
        assert!(reader.is_null());
        assert_eq!(
            ftl_rs_zip_open(b"abc".as_ptr(), 3, ptr::null_mut()),
            ERR_INVALID_PARAMETER
        );
        assert_eq!(
            ftl_rs_zip_open(b"abc".as_ptr(), 3, &mut reader),
            ERR_NOT_AN_ARCHIVE
        );
        assert!(reader.is_null());

        assert_eq!(ftl_rs_zip_num_files(ptr::null()), 0);
        let mut st = ZipStat::new();
        assert!(!ftl_rs_zip_file_stat(ptr::null(), 0, &mut st));
        assert!(!ftl_rs_zip_extract(ptr::null(), 0, ptr::null_mut(), 0));
        assert_eq!(ftl_rs_zip_last_error(ptr::null()), ERR_NONE);
        ftl_rs_zip_reader_free(ptr::null_mut());

        assert_eq!(ftl_rs_zip_validate(ptr::null(), 5), ERR_INVALID_PARAMETER);
        assert_eq!(ftl_rs_zip_validate(ptr::null(), 0), ERR_INVALID_PARAMETER);

        // A valid reader: a NULL buffer with a size, or a NULL name, are refused
        let bytes = raw(&[Raw::stored(b"a", b"abc")]);
        assert_eq!(ftl_rs_zip_open(bytes.as_ptr(), bytes.len(), &mut reader), ERR_NONE);
        assert!(!ftl_rs_zip_extract(reader, 0, ptr::null_mut(), 3));
        assert_eq!(ftl_rs_zip_last_error(reader), ERR_INVALID_PARAMETER);
        ftl_rs_zip_reader_free(reader);

        let writer: *mut ZipWriter = ftl_rs_zip_writer_new();
        assert_eq!(
            ftl_rs_zip_writer_add(writer, ptr::null(), ptr::null(), 0, ptr::null(), 0, 0),
            ERR_INVALID_PARAMETER
        );
        assert_eq!(
            ftl_rs_zip_writer_add(ptr::null_mut(), ptr::null(), ptr::null(), 0, ptr::null(), 0, 0),
            ERR_INVALID_PARAMETER
        );
        ftl_rs_zip_writer_free(writer);
        ftl_rs_zip_writer_free(ptr::null_mut());
    }
}

/// The base archives of the mutation pass: the teleporter's layout, an empty
/// archive, a hand-made one with the odd fields, and a ZIP64 one
fn base_archives() -> Vec<Vec<u8>> {
    let mut odd = Raw::stored(b"odd", b"abc");
    odd.flags = FLAG_ENCRYPTED;
    odd.comment = b"note".to_vec();
    odd.extra = zip64_extra(&[3]);
    odd.uncomp_size = 0xFFFF_FFFF;
    let mut method = Raw::deflated(b"m", &pattern(64));
    method.method = 12;
    vec![
        write_archive(vec![
            ("etc/pihole/pihole.toml", pattern(342), "note"),
            ("etc/pihole/dhcp.leases", Vec::new(), ""),
            ("etc/pihole/dir/", Vec::new(), ""),
            ("etc/x", noise(3, 9), ""),
        ]),
        Writer::new().finish().expect("finish"),
        raw(&[odd, method, Raw::deflated(b"d", &pattern(300))]),
        zip64(&[Raw::stored(b"z", b"abc")], 44),
    ]
}

#[test]
fn deterministic_mutations_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut runs = 0usize;
    for base in base_archives() {
        // Every truncation of each base
        for len in 0..base.len() {
            exercise(&base[..len]);
            runs += 1;
        }
        // A thousand mutations of each base, applied to the base only
        for _ in 0..1000 {
            let mut m = base.clone();
            mutate(&mut rng, &mut m);
            exercise(&m);
            runs += 1;
        }
    }
    assert!(runs >= 3000, "only {runs} runs");
}
