// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Tests of the gzip module: the committed vectors, round trips, header
//! variants, the log texts, the boundary functions and a deterministic mutation
//! test.

use std::ptr;
use std::slice;

use super::*;
use crate::buf::{ftl_rs_buf_free, FtlRsBuf};
use crate::sha256::digest;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/vectors/gzip/");
const FTEXT: u8 = 0x01;

/// The fields of an FtlRsBuf, which buf.rs keeps private. Same layout.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawBuf {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}

/// A buffer that holds nothing yet
fn empty_buf() -> FtlRsBuf {
    // SAFETY: all zeros is a NULL pointer with zero lengths, as FtlRsBuf::EMPTY
    unsafe { std::mem::zeroed() }
}

/// Copies out the bytes of a buffer the boundary wrote, and frees the buffer
fn take(mut buf: FtlRsBuf) -> Vec<u8> {
    // SAFETY: FtlRsBuf is repr(C) with the three fields of RawBuf
    let raw = unsafe { *(&buf as *const FtlRsBuf).cast::<RawBuf>() };
    let bytes = if raw.len == 0 {
        Vec::new()
    } else {
        // SAFETY: the boundary wrote raw.len initialised bytes at raw.ptr
        unsafe { slice::from_raw_parts(raw.ptr, raw.len) }.to_vec()
    };
    // SAFETY: buf came from the boundary and is not used after this
    unsafe { ftl_rs_buf_free(&mut buf) };
    bytes
}

/// xorshift64*: the same sequence for the same seed on every run
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A number below n, for n > 0
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
}

/// Deterministic test data of len bytes: text-like (kind 0), zeros (kind 1) or
/// random bytes (kind 2)
fn sample(len: usize, kind: u8) -> Vec<u8> {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ (len as u64) ^ (u64::from(kind) << 48));
    (0..len)
        .map(|_| match kind {
            0 => {
                if rng.below(6) == 0 {
                    b' '
                } else {
                    b'a' + rng.below(26) as u8
                }
            }
            1 => 0,
            _ => rng.next_u64() as u8,
        })
        .collect()
}

/// Raw DEFLATE data, the body of a gzip stream
fn raw_deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec(data, 6)
}

/// A gzip stream built by hand: the fixed header with the given method and
/// flags, the optional fields, the body, and a footer with the given CRC-32 and
/// ISIZE
fn assemble(method: u8, flags: u8, fields: &[u8], body: &[u8], crc: u32, out_size: u32) -> Vec<u8> {
    let mut stream = vec![0x1f, 0x8b, method, flags, 0, 0, 0, 0, 0, 3];
    stream.extend_from_slice(fields);
    stream.extend_from_slice(body);
    stream.extend_from_slice(&crc.to_le_bytes());
    stream.extend_from_slice(&out_size.to_le_bytes());
    stream
}

/// A valid stream of data with the given flags and optional fields
fn with_fields(flags: u8, fields: &[u8], data: &[u8]) -> Vec<u8> {
    assemble(8, flags, fields, &raw_deflate(data), crc32(data), data.len() as u32)
}

/// An FEXTRA field: XLEN, then the extra bytes
fn extra_field(extra: &[u8]) -> Vec<u8> {
    let mut field = (extra.len() as u16).to_le_bytes().to_vec();
    field.extend_from_slice(extra);
    field
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The value of key in one manifest entry: the text of a string, or the bare
/// word of a number or a bool
fn field<'a>(entry: &'a str, key: &str) -> Option<&'a str> {
    let rest = entry.split_once(&format!("\"{key}\": "))?.1;
    match rest.strip_prefix('"') {
        Some(quoted) => quoted.split_once('"').map(|(value, _)| value),
        None => rest
            .split(|c: char| matches!(c, ',' | '\n' | '}'))
            .next()
            .map(str::trim),
    }
}

#[test]
fn crc32_has_the_standard_check_values() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b"hello"), 0x3610_A686);
    assert_eq!(crc32(b""), 0);
}

/// Every vector in test/vectors/gzip/manifest.json. The manifest is written by
/// test/gzip_regression.c, with one entry per vector and no escapes in its
/// strings, so its fields are read as text.
#[test]
fn manifest_vectors_match_c() {
    let manifest = std::fs::read_to_string(format!("{VECTORS}manifest.json")).unwrap();
    let entries: Vec<&str> = manifest.split("\"file\": \"").skip(1).collect();
    assert!(!entries.is_empty(), "no vectors in the manifest");
    for entry in entries {
        let file = entry.split('"').next().unwrap();
        let bytes = std::fs::read(format!("{VECTORS}{file}")).unwrap();
        match field(entry, "rejected") {
            Some("true") => {
                let c_log = field(entry, "c_log").unwrap();
                let err = inflate(&bytes).expect_err(file);
                assert_eq!(err.message(), c_log, "{file}");
            }
            Some("false") => {
                let output = inflate(&bytes).unwrap_or_else(|err| panic!("{file}: {}", err.message()));
                let size: usize = field(entry, "output_size").unwrap().parse().unwrap();
                assert_eq!(output.len(), size, "{file}");
                assert_eq!(hex(&digest(&output)), field(entry, "output_sha256").unwrap(), "{file}");
            }
            other => panic!("{file}: no rejected flag ({other:?})"),
        }
    }
}

#[test]
fn error_messages_are_the_c_log_texts() {
    let cases = [
        (Error::NotGzip, "This is not a valid GZIP stream"),
        (Error::Method, "Compression algorithm not supported"),
        (Error::HeaderCrc, "Compression with extra fields not supported"),
        (Error::Extra, "Invalid GZIP header"),
        (Error::NameOverrun, "GZIP file name field overruns into the footer"),
        (Error::NameUnterminated, "File name is missing or invalid in GZIP header"),
        (Error::CommentOverrun, "GZIP file comment field overruns into the footer"),
        (Error::CommentUnterminated, "File comment is missing or invalid in GZIP header"),
        (Error::Size, "File is empty or too large"),
        (Error::Alloc(268_435_456), "Failed to allocate 268435456 bytes of memory"),
        (Error::Data, "Failed to uncompress: data error"),
        (Error::Buf, "Failed to uncompress: buf error"),
        (Error::Checksum, "Checksum mismatch"),
    ];
    for (error, text) in cases {
        assert_eq!(error.message(), text);
    }
}

#[test]
fn round_trips_of_many_lengths_and_kinds() {
    let lengths = (0..=40).chain([255, 256, 257, 1000, 4096, 65_535, 65_536, 70_000, 100_000]);
    for len in lengths {
        for kind in 0..3 {
            let data = sample(len, kind);
            let stream = deflate(&data, 0);
            if len == 0 {
                assert_eq!(inflate(&stream), Err(Error::Size));
            } else {
                assert_eq!(inflate(&stream), Ok(data), "length {len}, kind {kind}");
            }
        }
    }
}

#[test]
fn deflate_writes_the_fixed_header_and_footer() {
    let stream = deflate(b"hello", 0x0102_0304);
    assert_eq!(&stream[..10], &[0x1f, 0x8b, 0x08, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02, 0x03]);
    let footer = &stream[stream.len() - 8..];
    assert_eq!(&footer[..4], &crc32(b"hello").to_le_bytes());
    assert_eq!(&footer[4..], &5u32.to_le_bytes());
    assert_eq!(inflate(&stream), Ok(b"hello".to_vec()));
}

#[test]
fn empty_payload_is_rejected_as_too_large_like_c() {
    assert_eq!(inflate(&deflate(&[], 0)), Err(Error::Size));
    assert_eq!(Error::Size.message(), "File is empty or too large");
}

#[test]
fn optional_header_fields_are_skipped() {
    let data = sample(300, 0);
    // Every combination of FEXTRA, FNAME and FCOMMENT, with FTEXT set
    for combo in 0u8..8 {
        let mut flags = FTEXT;
        let mut fields = Vec::new();
        if combo & 1 != 0 {
            flags |= FEXTRA;
            fields.extend(extra_field(b"\0\x01xyz"));
        }
        if combo & 2 != 0 {
            flags |= FNAME;
            fields.extend_from_slice(b"name.txt\0");
        }
        if combo & 4 != 0 {
            flags |= FCOMMENT;
            fields.extend_from_slice(b"a comment\0");
        }
        assert_eq!(inflate(&with_fields(flags, &fields, &data)), Ok(data.clone()), "flags {flags:#04x}");
    }
    // An empty name and an empty comment are just their terminators
    assert_eq!(inflate(&with_fields(FNAME | FCOMMENT, b"\0\0", &data)), Ok(data.clone()));
    // An extra field of length 0
    assert_eq!(inflate(&with_fields(FEXTRA, &[0, 0], &data)), Ok(data));
}

#[test]
fn header_flags_and_method_are_checked_like_c() {
    assert_eq!(inflate(&with_fields(FHCRC, &[0, 0], b"x")), Err(Error::HeaderCrc));
    assert_eq!(inflate(&assemble(0, 0, &[], &raw_deflate(b"x"), crc32(b"x"), 1)), Err(Error::Method));
    assert_eq!(inflate(&assemble(9, 0, &[], &raw_deflate(b"x"), crc32(b"x"), 1)), Err(Error::Method));
}

#[test]
fn short_or_non_gzip_input_is_rejected() {
    assert_eq!(inflate(&[]), Err(Error::NotGzip));
    // 17 bytes: one short of a header and a footer
    let short = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(inflate(&short), Err(Error::NotGzip));
    let mut stream = with_fields(0, &[], b"x");
    stream[0] = 0x1e;
    assert_eq!(inflate(&stream), Err(Error::NotGzip));
}

#[test]
fn extra_field_must_end_before_the_footer() {
    assert_eq!(inflate(&assemble(8, FEXTRA, &[0xff, 0xff], &[], 0, 1)), Err(Error::Extra));
    // Extra fields that end exactly at the footer leave no DEFLATE data
    assert_eq!(inflate(&assemble(8, FEXTRA, &[0, 0], &[], 0, 1)), Err(Error::Data));
    assert_eq!(inflate(&assemble(8, FEXTRA, &[1, 0, 9], &[], 0, 1)), Err(Error::Data));
}

#[test]
fn name_and_comment_must_end_before_the_footer() {
    // No room for the field at all
    assert_eq!(inflate(&assemble(8, FNAME, &[], &[], 0, 1)), Err(Error::NameOverrun));
    assert_eq!(inflate(&assemble(8, FCOMMENT, &[], &[], 0, 1)), Err(Error::CommentOverrun));
    // No terminator before the footer
    assert_eq!(inflate(&assemble(8, FNAME, b"abc", &[], 0, 1)), Err(Error::NameUnterminated));
    assert_eq!(inflate(&assemble(8, FCOMMENT, b"note", &[], 0, 1)), Err(Error::CommentUnterminated));
    // The terminator is the last byte before the footer, so no DEFLATE data is left
    assert_eq!(inflate(&assemble(8, FNAME, b"a\0", &[], 0, 1)), Err(Error::Data));
    assert_eq!(inflate(&assemble(8, FCOMMENT, b"a\0", &[], 0, 1)), Err(Error::Data));
}

#[test]
fn isize_must_be_within_the_c_limit() {
    let stream = |out_size| assemble(8, 0, &[], &raw_deflate(b"hello"), crc32(b"hello"), out_size);
    assert_eq!(inflate(&stream(0)), Err(Error::Size));
    assert_eq!(inflate(&stream(0x1000_0001)), Err(Error::Size));
    assert_eq!(inflate(&stream(u32::MAX)), Err(Error::Size));
    // The largest accepted ISIZE: a 256 MiB buffer of which 5 bytes are used
    assert_eq!(inflate(&stream(0x1000_0000)), Ok(b"hello".to_vec()));
}

#[test]
fn isize_only_sizes_the_output_buffer() {
    // A larger ISIZE than the data: the output has the decoded length
    let larger = assemble(8, 0, &[], &raw_deflate(b"hello"), crc32(b"hello"), 100);
    assert_eq!(inflate(&larger), Ok(b"hello".to_vec()));
    // A smaller ISIZE: the DEFLATE output does not fit
    let smaller = assemble(8, 0, &[], &raw_deflate(b"hello"), crc32(b"hello"), 3);
    assert_eq!(inflate(&smaller), Err(Error::Buf));
}

#[test]
fn checksum_is_checked_and_trailing_bytes_are_ignored() {
    let body = raw_deflate(b"hello");
    assert_eq!(inflate(&assemble(8, 0, &[], &body, crc32(b"hellp"), 5)), Err(Error::Checksum));
    // Bytes between the end of the DEFLATE stream and the footer are ignored
    let trailing = [body, vec![1, 2, 3]].concat();
    assert_eq!(inflate(&assemble(8, 0, &[], &trailing, crc32(b"hello"), 5)), Ok(b"hello".to_vec()));
}

#[test]
fn corrupt_or_truncated_deflate_is_a_data_error() {
    // Block type 3 is reserved
    assert_eq!(inflate(&assemble(8, 0, &[], &[0x07], 0, 1)), Err(Error::Data));
    let data = sample(1000, 0);
    let body = raw_deflate(&data);
    let cut = &body[..body.len() / 2];
    assert_eq!(inflate(&assemble(8, 0, &[], cut, crc32(&data), 1000)), Err(Error::Data));
}

#[test]
fn boundary_round_trips_and_reports_messages() {
    let data = sample(1000, 0);
    let mut stream = empty_buf();
    // SAFETY: data is valid for its length, and stream is a buffer that C owns
    assert!(unsafe { ftl_rs_gzip_deflate(data.as_ptr(), data.len(), 1_700_000_000, &mut stream) });
    let bytes = take(stream);
    assert_eq!(bytes, deflate(&data, 1_700_000_000));

    let mut out = empty_buf();
    let mut message = empty_buf();
    // SAFETY: bytes is valid for its length, and the buffers are owned by C
    assert!(unsafe { ftl_rs_gzip_inflate(bytes.as_ptr(), bytes.len(), &mut out, &mut message) });
    assert_eq!(take(out), data);
    assert!(take(message).is_empty());

    // A rejected stream gives its message, and out is not written
    let mut out = empty_buf();
    let mut message = empty_buf();
    // SAFETY: the first 10 bytes of bytes are valid, and the buffers are owned by C
    assert!(!unsafe { ftl_rs_gzip_inflate(bytes.as_ptr(), 10, &mut out, &mut message) });
    assert_eq!(take(message), b"This is not a valid GZIP stream".to_vec());
}

#[test]
fn boundary_rejects_null_arguments_without_crashing() {
    let data = [0u8; 40];
    let mut out = empty_buf();
    let mut message = empty_buf();
    // SAFETY: NULL with length 0 is allowed; the buffers are owned by C
    assert!(!unsafe { ftl_rs_gzip_inflate(ptr::null(), 0, &mut out, &mut message) });
    assert_eq!(take(message), b"This is not a valid GZIP stream".to_vec());

    let mut message = empty_buf();
    // SAFETY: NULL with a length is rejected as not gzip
    assert!(!unsafe { ftl_rs_gzip_inflate(ptr::null(), data.len(), &mut out, &mut message) });
    assert_eq!(take(message), b"This is not a valid GZIP stream".to_vec());

    let mut message = empty_buf();
    // SAFETY: data is valid; out is NULL, so nothing is written
    assert!(!unsafe { ftl_rs_gzip_inflate(data.as_ptr(), data.len(), ptr::null_mut(), &mut message) });
    assert!(take(message).is_empty());

    // SAFETY: NULL with a length cannot be compressed
    assert!(!unsafe { ftl_rs_gzip_deflate(ptr::null(), 5, 0, &mut out) });
    // SAFETY: NULL with length 0 is an empty input, which deflates to a stream
    assert!(unsafe { ftl_rs_gzip_deflate(ptr::null(), 0, 0, &mut out) });
    assert_eq!(inflate(&take(out)), Err(Error::Size));
}

/// Valid streams to mutate: the plain header, every optional field, and a few bodies
fn seeds() -> Vec<Vec<u8>> {
    let fields = [extra_field(b"xy"), b"name.txt\0".to_vec(), b"a comment\0".to_vec()].concat();
    vec![
        with_fields(0, &[], &sample(20, 0)),
        with_fields(FTEXT | FEXTRA | FNAME | FCOMMENT, &fields, &sample(200, 0)),
        with_fields(FNAME, b"n\0", &sample(300, 2)),
        with_fields(0, &[], &sample(64, 1)),
    ]
}

/// Values that make size and flag fields edge cases
const EDGE_VALUES: [u32; 9] = [0, 1, 0x7f, 0x80, 0xffff, 0x0fff_ffff, 0x1000_0000, 0x1000_0001, 0xffff_ffff];

/// Writes value as 4 little-endian bytes at at, if they fit
fn put(bytes: &mut [u8], at: usize, value: u32) {
    if let Some(field) = bytes.get_mut(at..).and_then(|rest| rest.get_mut(..4)) {
        field.copy_from_slice(&value.to_le_bytes());
    }
}

/// One deterministic mutation of seed: bit flips, a truncation, a size or flag
/// field set to an edge value, random bytes, or bytes inserted or deleted
fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut bytes = seed.to_vec();
    let len = bytes.len();
    match rng.below(5) {
        0 => {
            for _ in 0..=rng.below(4) {
                let at = rng.below(len);
                bytes[at] ^= 1 << rng.below(8);
            }
        }
        1 => bytes.truncate(rng.below(len + 1)),
        2 => {
            // The method, flags, XLEN, ISIZE and CRC-32 fields
            let fields = [2, 3, 10, len.saturating_sub(4), len.saturating_sub(8)];
            let value = if rng.below(2) == 0 {
                EDGE_VALUES[rng.below(EDGE_VALUES.len())]
            } else {
                rng.next_u64() as u32
            };
            put(&mut bytes, fields[rng.below(fields.len())], value);
        }
        3 => {
            bytes = (0..rng.below(64)).map(|_| rng.next_u64() as u8).collect();
            if rng.below(2) == 0 {
                if let Some(head) = bytes.get_mut(..3) {
                    head.copy_from_slice(&[0x1f, 0x8b, 0x08]);
                }
            }
        }
        _ => {
            let at = rng.below(len + 1);
            if rng.below(2) == 0 {
                let count = 1 + rng.below(8);
                for i in 0..count {
                    bytes.insert(at + i, rng.next_u64() as u8);
                }
            } else {
                let end = (at + 1 + rng.below(16)).min(len);
                bytes.drain(at..end);
            }
        }
    }
    bytes
}

/// Decodes bytes and checks that the output stays within MAX_OUTPUT. Returns
/// whether the stream was accepted.
fn decode_bounded(bytes: &[u8]) -> bool {
    match inflate(bytes) {
        Ok(output) => {
            assert!(output.len() <= MAX_OUTPUT);
            true
        }
        Err(_) => false,
    }
}

/// Every prefix of the small seeds, then 3000 seeded mutations. A panic fails
/// the test, and the output of every accepted stream must stay within MAX_OUTPUT.
#[test]
fn truncations_and_mutations_never_panic_and_stay_bounded() {
    const MUTATIONS: usize = 3000;
    let seeds = seeds();
    for seed in &seeds {
        assert!(decode_bounded(seed), "seed is not valid");
        if seed.len() <= 512 {
            for cut in 0..seed.len() {
                decode_bounded(&seed[..cut]);
            }
        }
    }
    let mut rng = Rng(0x0123_4567_89AB_CDEF);
    let (mut accepted, mut rejected) = (0usize, 0usize);
    for _ in 0..MUTATIONS {
        let seed = &seeds[rng.below(seeds.len())];
        if decode_bounded(&mutate(seed, &mut rng)) {
            accepted += 1;
        } else {
            rejected += 1;
        }
    }
    assert!(accepted > 0 && rejected > 0, "accepted {accepted}, rejected {rejected}");
}
