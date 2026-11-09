// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Tests of the tar reader: every vector of test/vectors/tar, the size field
//! and span rules, the edge cases of find and list, and a deterministic
//! mutation test (no panic, output inside the archive).

use std::ffi::CString;
use std::fs;
use std::mem::size_of;
use std::ptr;
use std::slice;

use super::*;
use crate::buf::{ftl_rs_buf_free, FtlRsBuf};

const USIZE: usize = size_of::<usize>();

/// The fields of an FtlRsBuf, which are private to buf.rs. The mirror has the
/// same repr(C) layout, and the assertion checks the size.
#[repr(C)]
struct Parts {
    ptr: *mut u8,
    len: usize,
    cap: usize,
}
const _: () = assert!(size_of::<Parts>() == size_of::<FtlRsBuf>());

fn parts(buf: &FtlRsBuf) -> &Parts {
    // SAFETY: both types are repr(C) with the same three fields
    unsafe { &*(buf as *const FtlRsBuf).cast::<Parts>() }
}

/// The entries in a buffer from ftl_rs_tar_list()
fn decode(buf: &FtlRsBuf) -> Vec<Entry> {
    let parts = parts(buf);
    assert_eq!(parts.len % RECORD_LEN, 0);
    if parts.ptr.is_null() {
        return Vec::new();
    }
    // SAFETY: ptr holds len initialised bytes (see buf.rs)
    let bytes = unsafe { slice::from_raw_parts(parts.ptr, parts.len) };
    bytes
        .chunks_exact(RECORD_LEN)
        .map(|record| Entry {
            offset: read_usize(&record[..USIZE]),
            size: read_usize(&record[USIZE..]),
        })
        .collect()
}

fn read_usize(bytes: &[u8]) -> usize {
    usize::from_ne_bytes(bytes.try_into().unwrap())
}

/// ftl_rs_tar_find() as C calls it: the payload offset and size if found
fn c_find(tar: &[u8], name: &[u8]) -> Option<(usize, usize)> {
    let name = CString::new(name).unwrap();
    let (mut offset, mut size) = (usize::MAX, usize::MAX);
    let found = unsafe { ftl_rs_tar_find(tar.as_ptr(), tar.len(), name.as_ptr(), &mut offset, &mut size) };
    if found {
        Some((offset, size))
    } else {
        assert_eq!((offset, size), (0, 0), "a miss writes 0 to both outputs");
        None
    }
}

/// ftl_rs_tar_list() as C calls it, with the buffer freed
fn c_list(tar: &[u8]) -> Vec<Entry> {
    let mut buf = unsafe { ftl_rs_tar_list(tar.as_ptr(), tar.len()) };
    let entries = decode(&buf);
    unsafe { ftl_rs_buf_free(&mut buf) };
    entries
}

/// The name of a listed entry: its name field up to the NUL
fn name_of(tar: &[u8], entry: Entry) -> &[u8] {
    let field = &tar[entry.offset..entry.offset + NAME_LEN];
    let len = field.iter().position(|&byte| byte == 0).expect("a listed name ends with a NUL");
    &field[..len]
}

/// A header block: the name (NUL-terminated when shorter than the field), the
/// size field, the magic and the version
fn header(name: &[u8], size_field: &[u8; SIZE_LEN]) -> [u8; BLOCK] {
    let mut block = [0u8; BLOCK];
    block[..name.len()].copy_from_slice(name);
    block[SIZE_OFFSET..SIZE_OFFSET + SIZE_LEN].copy_from_slice(size_field);
    block[MAGIC_OFFSET..MAGIC_OFFSET + 6].copy_from_slice(b"ustar\0");
    block[MAGIC_OFFSET + 6..MAGIC_OFFSET + 8].copy_from_slice(b"00");
    block
}

/// An 11-digit octal size field with its NUL
fn octal(value: u64) -> [u8; SIZE_LEN] {
    format!("{value:011o}\0").as_bytes().try_into().expect("11 digits fit the field")
}

/// A 12-digit octal size field, with no NUL
fn oct12(value: u64) -> [u8; SIZE_LEN] {
    format!("{value:012o}").as_bytes().try_into().expect("12 digits fit the field")
}

/// A 12-byte field from a literal, so that a miscounted literal fails the test
fn field12(bytes: &[u8]) -> [u8; SIZE_LEN] {
    bytes.try_into().expect("a size field is 12 bytes")
}

/// An archive of entries with the given names and sizes (data is a pattern),
/// followed by two zero blocks
fn archive_of<S: AsRef<str>>(entries: &[(S, usize)]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (name, size) in entries {
        tar.extend_from_slice(&header(name.as_ref().as_bytes(), &octal(*size as u64)));
        let padded = size.div_ceil(BLOCK) * BLOCK;
        tar.extend((0..padded).map(|i| if i < *size { b'A' + (i % 26) as u8 } else { 0 }));
    }
    tar.extend_from_slice(&[0; 2 * BLOCK]);
    tar
}

/// What must hold for any archive: the entries lie inside it, both find and
/// list agree with the boundary, and the boundary buffer holds one record per
/// entry and no more than the archive length allows.
fn check_archive(tar: &[u8], names: &[&[u8]]) {
    let entries = list_entries(tar);
    assert!(entries.len() <= tar.len() / BLOCK);
    for entry in &entries {
        assert!(entry.offset + BLOCK + entry.size <= tar.len());
    }
    assert_eq!(c_list(tar), entries);
    let listed = entries.iter().map(|entry| name_of(tar, *entry));
    for name in names.iter().copied().chain(listed) {
        let found = find_entry(tar, name);
        if let Some((offset, size)) = found {
            assert!(offset + size <= tar.len());
        }
        assert_eq!(c_find(tar, name), found);
    }

    let mut buf = unsafe { ftl_rs_tar_list(tar.as_ptr(), tar.len()) };
    assert!(parts(&buf).cap <= 2 * RECORD_LEN * (tar.len() / BLOCK + 1));
    unsafe { ftl_rs_buf_free(&mut buf) };
}

/// A xorshift generator, so that the mutations are the same on every run
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// A size field for a mutation: 0, the largest 11-digit value, 12 digits,
/// small octal, spaces, a bad digit, or random bytes
fn size_field(rng: &mut Rng) -> [u8; SIZE_LEN] {
    match rng.below(9) {
        0 => octal(0),
        1 => octal((1 << 33) - 1),
        2 => field12(b"777777777777"),
        3 => octal(rng.below(1 << 20) as u64),
        4 => field12(b"            "),
        5 => field12(b"0000000x000\0"),
        6 => field12(b"00000000008\0"),
        7 => [(); SIZE_LEN].map(|_| rng.next_u64() as u8),
        _ => oct12(rng.next_u64() & ((1 << 36) - 1)),
    }
}

/// One mutation: a bit flip, a random byte, a truncation, a size field, a
/// name byte, a magic byte, or a random block inserted at a block boundary
fn mutate(tar: &mut Vec<u8>, rng: &mut Rng) {
    let blocks = tar.len() / BLOCK;
    match rng.below(7) {
        0 if !tar.is_empty() => {
            let at = rng.below(tar.len());
            tar[at] ^= 1 << rng.below(8);
        }
        1 if !tar.is_empty() => {
            let at = rng.below(tar.len());
            tar[at] = rng.next_u64() as u8;
        }
        2 => {
            let len = rng.below(tar.len() + 1);
            tar.truncate(len);
        }
        3 if blocks > 0 => {
            let at = rng.below(blocks) * BLOCK + SIZE_OFFSET;
            tar[at..at + SIZE_LEN].copy_from_slice(&size_field(rng));
        }
        4 if blocks > 0 => {
            let at = rng.below(blocks) * BLOCK + rng.below(NAME_LEN);
            tar[at] = [0, b'x', 0xff][rng.below(3)];
        }
        5 if blocks > 0 => {
            let at = rng.below(blocks) * BLOCK + MAGIC_OFFSET + rng.below(8);
            tar[at] = rng.next_u64() as u8;
        }
        _ => {
            let at = rng.below(blocks + 1) * BLOCK;
            let block: Vec<u8> = (0..BLOCK).map(|_| rng.next_u64() as u8).collect();
            tar.splice(at..at, block);
        }
    }
}

/// A parsed JSON value. The manifest uses only these.
#[derive(Debug)]
enum Json {
    Null,
    Bool(bool),
    Num(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

/// A small JSON reader for the manifest (the vendored crates have no serde)
struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&mut self) -> Option<u8> {
        while matches!(self.text.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
        self.text.get(self.pos).copied()
    }

    fn take(&mut self, byte: u8) {
        assert_eq!(self.peek(), Some(byte), "JSON: expected '{}' at byte {}", byte as char, self.pos);
        self.pos += 1;
    }

    fn value(&mut self) -> Json {
        match self.peek() {
            Some(b'{') => {
                self.take(b'{');
                let mut fields = Vec::new();
                while self.peek() != Some(b'}') {
                    if !fields.is_empty() {
                        self.take(b',');
                    }
                    let key = self.string();
                    self.take(b':');
                    fields.push((key, self.value()));
                }
                self.take(b'}');
                Json::Obj(fields)
            }
            Some(b'[') => {
                self.take(b'[');
                let mut items = Vec::new();
                while self.peek() != Some(b']') {
                    if !items.is_empty() {
                        self.take(b',');
                    }
                    items.push(self.value());
                }
                self.take(b']');
                Json::Arr(items)
            }
            Some(b'"') => Json::Str(self.string()),
            Some(b't') => self.word("true", Json::Bool(true)),
            Some(b'f') => self.word("false", Json::Bool(false)),
            Some(b'n') => self.word("null", Json::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            other => panic!("JSON: unexpected {other:?} at byte {}", self.pos),
        }
    }

    fn word(&mut self, word: &str, value: Json) -> Json {
        assert!(self.text[self.pos..].starts_with(word.as_bytes()), "JSON: expected {word}");
        self.pos += word.len();
        value
    }

    fn number(&mut self) -> Json {
        let start = self.pos;
        if self.text[self.pos] == b'-' {
            self.pos += 1;
        }
        while matches!(self.text.get(self.pos), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let digits = std::str::from_utf8(&self.text[start..self.pos]).unwrap();
        Json::Num(digits.parse().expect("JSON: an integer"))
    }

    fn string(&mut self) -> String {
        self.take(b'"');
        let mut out = Vec::new();
        loop {
            let byte = *self.text.get(self.pos).expect("JSON: unterminated string");
            self.pos += 1;
            match byte {
                b'"' => break,
                b'\\' => {
                    let escaped = *self.text.get(self.pos).expect("JSON: escape at the end");
                    self.pos += 1;
                    match escaped {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'u' => {
                            let hex = std::str::from_utf8(&self.text[self.pos..self.pos + 4]).unwrap();
                            self.pos += 4;
                            let ch = char::from_u32(u32::from_str_radix(hex, 16).unwrap()).unwrap();
                            out.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
                        }
                        other => out.push(other),
                    }
                }
                _ => out.push(byte),
            }
        }
        String::from_utf8(out).expect("JSON: a string is UTF-8")
    }
}

fn parse_json(text: &[u8]) -> Json {
    let mut parser = Parser { text, pos: 0 };
    let value = parser.value();
    assert!(parser.peek().is_none(), "JSON: data after the value");
    value
}

fn field<'a>(object: &'a Json, key: &str) -> &'a Json {
    match object {
        Json::Obj(fields) => &fields.iter().find(|(name, _)| name == key).unwrap_or_else(|| panic!("JSON: no {key}")).1,
        other => panic!("JSON: {key} of {other:?}"),
    }
}

fn as_str(value: &Json) -> &str {
    match value {
        Json::Str(s) => s,
        other => panic!("JSON: expected a string, got {other:?}"),
    }
}

fn as_num(value: &Json) -> i64 {
    match value {
        Json::Num(n) => *n,
        other => panic!("JSON: expected a number, got {other:?}"),
    }
}

fn as_bool(value: &Json) -> bool {
    match value {
        Json::Bool(b) => *b,
        Json::Null => false,
        other => panic!("JSON: expected a boolean, got {other:?}"),
    }
}

fn as_arr(value: &Json) -> &[Json] {
    match value {
        Json::Arr(items) => items,
        other => panic!("JSON: expected an array, got {other:?}"),
    }
}

/// Every vector of test/vectors/tar/manifest.json, run through the boundary
/// functions as C calls them, gives the manifest's result.
#[test]
fn vectors_match_the_manifest() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../test/vectors/tar/");
    let manifest = parse_json(&fs::read(format!("{dir}manifest.json")).expect("manifest.json"));
    assert_eq!(as_str(field(&manifest, "module")), "tar");
    let vectors = as_arr(field(&manifest, "vectors"));
    assert!(!vectors.is_empty());

    for vector in vectors {
        let file = as_str(field(vector, "file"));
        let tar = fs::read(format!("{dir}{file}")).unwrap_or_else(|e| panic!("{file}: {e}"));
        let expect = field(vector, "expect");
        match as_str(field(vector, "op")) {
            "find_file_in_tar" => {
                let name = as_str(field(field(vector, "args"), "name"));
                let found = c_find(&tar, name.as_bytes());
                assert_eq!(found.is_some(), as_bool(field(expect, "found")), "{file}: found");
                let (offset, size) = found.unwrap_or((0, 0));
                assert_eq!(size as i64, as_num(field(expect, "file_size")), "{file}: file_size");
                if found.is_some() {
                    assert_eq!(offset as i64, as_num(field(expect, "payload_offset")), "{file}: payload_offset");
                }
            }
            "list_files_in_tar" => {
                let listed: Vec<(String, i64)> = c_list(&tar)
                    .iter()
                    .map(|entry| {
                        let name = String::from_utf8(name_of(&tar, *entry).to_vec()).unwrap();
                        (name, entry.size as i64)
                    })
                    .collect();
                let wanted: Vec<(String, i64)> = as_arr(field(expect, "files"))
                    .iter()
                    .map(|file| (as_str(field(file, "name")).to_string(), as_num(field(file, "size"))))
                    .collect();
                assert_eq!(listed, wanted, "{file}: files");
            }
            op => panic!("{file}: unknown op {op}"),
        }
    }
}

/// The octal size fields, as tar.c reads them (see parse_size())
#[test]
fn size_fields_parse_as_tar_c_parses_them() {
    // The type makes each literal exactly SIZE_LEN bytes long
    let cases: [(&[u8; SIZE_LEN], Option<usize>); 17] = [
        (b"00000000000\0", Some(0)),
        (b"00000000777\0", Some(511)),
        (b"77777777777\0", Some(0o77777777777)),
        (b"777777777777", Some(0o777777777777)),
        (b"000000000001", Some(1)),
        (b"   00000001 ", Some(1)),
        (b"0000000000\0 ", Some(0)),
        (b"        1\0\0\0", Some(1)),
        (b"1\0\0\0\0\0\0\0\0\0\0\0", Some(1)),
        (b"            ", None),
        (b"\0\0\0\0\0\0\0\0\0\0\0\0", None),
        (b"           \0", None),
        (b"00000000008\0", None),
        (b"0000000x000\0", None),
        (b"1 1\0\0\0\0\0\0\0\0\0", None),
        (b"1\x001000000000", None),
        (b"0000\x00000001 ", None),
    ];
    for (field, expected) in cases {
        assert_eq!(parse_size(field), expected, "field {field:?}");
    }
}

#[test]
fn entry_span_is_the_header_plus_the_rounded_data() {
    assert_eq!(entry_span(0), Some(512));
    assert_eq!(entry_span(1), Some(1024));
    assert_eq!(entry_span(511), Some(1024));
    assert_eq!(entry_span(512), Some(1024));
    assert_eq!(entry_span(513), Some(1536));
    // The largest sizes that fit: a span of usize::MAX - 511 at most
    assert_eq!(entry_span(usize::MAX - 1024), Some(usize::MAX - 511));
    assert_eq!(entry_span(usize::MAX - 1023), Some(usize::MAX - 511));
    assert_eq!(entry_span(usize::MAX - 1022), None);
    assert_eq!(entry_span(usize::MAX), None);
}

/// find and list at the edges of the walk, as tar.c treats them
#[test]
fn find_and_list_follow_tar_c_at_the_edges() {
    // The last entry lacks its padding: its data fits, so list keeps it
    let mut tar = header(b"last", &octal(2)).to_vec();
    tar.extend_from_slice(b"xy");
    assert_eq!(tar.len(), 514);
    assert_eq!(list_entries(&tar), [Entry { offset: 0, size: 2 }]);
    assert_eq!(find_entry(&tar, b"last"), Some((512, 2)));
    // Another name stops at that entry, whose span runs past the end
    assert_eq!(find_entry(&tar, b"other"), None);

    // Data cut short: the entry is neither listed nor found
    let mut tar = header(b"cut", &octal(4)).to_vec();
    tar.extend_from_slice(b"xy");
    assert!(list_entries(&tar).is_empty());
    assert_eq!(find_entry(&tar, b"cut"), None);

    // A zero block ends the walk, so an entry after it is not seen
    let mut tar = header(b"a", &octal(0)).to_vec();
    tar.extend_from_slice(&[0; BLOCK]);
    tar.extend_from_slice(&header(b"b", &octal(0)));
    assert_eq!(list_entries(&tar), [Entry { offset: 0, size: 0 }]);
    assert_eq!(find_entry(&tar, b"b"), None);

    // A 99-byte name has its NUL in the field; a 100-byte name has none and
    // ends the walk
    let long = "n".repeat(99);
    let mut tar = header(b"ok", &octal(0)).to_vec();
    tar.extend_from_slice(&header(long.as_bytes(), &octal(0)));
    tar.extend_from_slice(&header(&[b'm'; 100], &octal(0)));
    tar.extend_from_slice(&header(b"after", &octal(0)));
    assert_eq!(list_entries(&tar).len(), 2);
    assert_eq!(find_entry(&tar, long.as_bytes()), Some((1024, 0)));
    assert_eq!(find_entry(&tar, &[b'm'; 100]), None);
    assert_eq!(find_entry(&tar, b"after"), None);

    // The name ends at its NUL: bytes after it are not part of the name
    let mut tar = header(b"abc", &octal(0)).to_vec();
    tar[4..11].copy_from_slice(b"garbage");
    assert_eq!(find_entry(&tar, b"abc"), Some((512, 0)));
    assert_eq!(name_of(&tar, Entry { offset: 0, size: 0 }), b"abc");

    // The first entry with a name is the one found
    let mut tar = header(b"dup", &octal(1)).to_vec();
    tar.extend_from_slice(&[b'x'; BLOCK]);
    tar.extend_from_slice(&header(b"dup", &octal(3)));
    tar.extend_from_slice(&[b'y'; BLOCK]);
    assert_eq!(find_entry(&tar, b"dup"), Some((512, 1)));

    // A match whose data does not fit fails the search
    let tar = header(b"dup", &octal(9)).to_vec();
    assert_eq!(find_entry(&tar, b"dup"), None);

    // Magic: "ustar" followed by any two bytes is a header (GNU writes
    // "ustar  \0"); a different magic is not
    let mut gnu = header(b"gnu", &octal(0)).to_vec();
    gnu[MAGIC_OFFSET + 5..MAGIC_OFFSET + 8].copy_from_slice(b"  \0");
    assert_eq!(list_entries(&gnu).len(), 1);
    let mut bad = header(b"bad", &octal(0)).to_vec();
    bad[MAGIC_OFFSET] = b'U';
    assert!(list_entries(&bad).is_empty());
}

/// A size that fits usize but runs far past the archive ends the walk. Neither
/// find nor list reads the header after it.
#[test]
fn sizes_past_the_end_end_the_walk() {
    let mut tar = header(b"huge", &field12(b"777777777777")).to_vec();
    tar.extend_from_slice(&header(b"after", &octal(0)));
    assert!(list_entries(&tar).is_empty());
    assert_eq!(find_entry(&tar, b"huge"), None);
    assert_eq!(find_entry(&tar, b"after"), None);
    let names: [&[u8]; 2] = [b"huge", b"after"];
    check_archive(&tar, &names);
}

/// NULL and empty archives, and a NULL name, find nothing and list nothing
#[test]
fn null_and_empty_arguments_find_nothing() {
    let tar = archive_of(&[("a", 1)]);
    let name = CString::new("a").unwrap();
    let (mut offset, mut size) = (7usize, 7usize);
    let found = unsafe { ftl_rs_tar_find(ptr::null(), 4096, name.as_ptr(), &mut offset, &mut size) };
    assert!(!found);
    assert_eq!((offset, size), (0, 0));

    let found = unsafe { ftl_rs_tar_find(tar.as_ptr(), tar.len(), ptr::null(), ptr::null_mut(), ptr::null_mut()) };
    assert!(!found);

    // NULL outputs are not written
    let found = unsafe { ftl_rs_tar_find(tar.as_ptr(), tar.len(), name.as_ptr(), ptr::null_mut(), ptr::null_mut()) };
    assert!(found);

    assert!(c_list(&[]).is_empty());
    let mut buf = unsafe { ftl_rs_tar_list(ptr::null(), 4096) };
    assert!(decode(&buf).is_empty());
    unsafe { ftl_rs_buf_free(&mut buf) };
}

/// Every truncation of an archive keeps its results inside the bytes given
#[test]
fn every_truncation_stays_inside_the_archive() {
    let tar = archive_of(&[("first", 3), ("second", 700), ("third", 0)]);
    let names: [&[u8]; 4] = [b"first", b"second", b"third", b"absent"];
    for len in 0..=tar.len() {
        check_archive(&tar[..len], &names);
    }
}

/// Deterministic mutations of valid archives: no panic, and every result
/// inside the archive
#[test]
fn mutated_archives_never_panic_and_stay_bounded() {
    let long = "n".repeat(99);
    let bases = [
        archive_of(&[("adlist.json", 0), ("pihole.toml", 513), (long.as_str(), 1024)]),
        archive_of(&[("gravity.db", 2048), ("dir/sub/file", 1), ("", 3)]),
        archive_of(&[("a", 511), ("b", 512), ("c", 513), ("d", 0), ("e", 1)]),
    ];
    let names: [&[u8]; 4] = [b"adlist.json", b"pihole.toml", b"dir/sub/file", b"absent"];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for i in 0..3000 {
        let mut tar = bases[i % bases.len()].clone();
        for _ in 0..1 + rng.below(3) {
            mutate(&mut tar, &mut rng);
        }
        check_archive(&tar, &names);
    }
}
