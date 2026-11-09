// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! SHA-256 (FIPS 180-4) for pihole-FTL sha256sum and the config/binary
//! checksums. Phase 2 module: replaces sha256sum() in src/files.c.
//!
//! Files are read until EOF. With skip_end, the last 32 bytes are held back
//! while reading and dropped at EOF, so no file size is needed (see
//! hash_reader()).

use std::ffi::{c_char, c_int, CStr, OsStr};
use std::fs::File;
use std::io::{self, ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::slice;

/// Size of a SHA-256 digest in bytes
pub const DIGEST_LEN: usize = 32;

/// Bytes read per call by hash_reader()
const CHUNK_LEN: usize = 64 * 1024;

/// Linux errno values returned to C (the same on every architecture)
const EINVAL: c_int = 22;
const EIO: c_int = 5;

/// Initial hash value, FIPS 180-4 section 5.3.3
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants, FIPS 180-4 section 4.2.2
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Streaming SHA-256 state
pub struct Sha256 {
    state: [u32; 8],
    /// Bytes not yet compressed, the first `block_len` of them are used
    block: [u8; 64],
    block_len: usize,
    /// Bytes hashed so far, modulo 2^64
    total_len: u64,
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            state: H0,
            block: [0; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    /// Adds `data` to the message. Any split of the input gives the same digest.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        // Finish the partial block first
        if self.block_len > 0 {
            let take = (64 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len < 64 {
                return;
            }
            compress(&mut self.state, &self.block);
            self.block_len = 0;
        }

        let mut blocks = data.chunks_exact(64);
        for block in blocks.by_ref() {
            compress(&mut self.state, block);
        }
        let rest = blocks.remainder();
        self.block[..rest.len()].copy_from_slice(rest);
        self.block_len = rest.len();
    }

    /// Pads the message (FIPS 180-4 section 5.1.1) and returns the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let bit_len = self.total_len.wrapping_mul(8);

        // A 0x80 byte, zeros up to 56 bytes mod 64, then the length in bits
        // as 64-bit big endian. The zeros are (119 - block_len) % 64 bytes
        // long, so the padding always fits in 72 bytes.
        let zeros = (119 - self.block_len) % 64;
        let mut padding = [0u8; 72];
        padding[0] = 0x80;
        let padding_len = 1 + zeros + 8;
        padding[1 + zeros..padding_len].copy_from_slice(&bit_len.to_be_bytes());
        self.update(&padding[..padding_len]);

        let mut out = [0u8; DIGEST_LEN];
        for (bytes, word) in out.chunks_exact_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Hashes `data` in one go.
pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Hashes everything `reader` returns until EOF. With `skip_end`, the last 32
/// bytes are left out, so a file shorter than 32 bytes hashes to the digest of
/// the empty message.
///
/// Up to 32 bytes are kept back in `buf[..held]`. Each read goes after them,
/// and everything before the last 32 bytes is hashed. At EOF the held bytes
/// are the trailer and are dropped.
pub fn hash_reader(reader: &mut impl Read, skip_end: bool) -> io::Result<[u8; DIGEST_LEN]> {
    let keep = if skip_end { DIGEST_LEN } else { 0 };
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; keep + CHUNK_LEN];
    let mut held = 0;
    loop {
        let n = match reader.read(&mut buf[held..]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let total = held + n;
        let ready = total.saturating_sub(keep);
        hasher.update(&buf[..ready]);
        buf.copy_within(ready..total, 0);
        held = total - ready;
    }
    Ok(hasher.finalize())
}

/// One 64-byte block of the compression function, FIPS 180-4 section 6.2.2
fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        let b = &block[4 * i..4 * i + 4];
        *word = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    }
    for i in 16..64 {
        let sigma0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let sigma1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(sigma0)
            .wrapping_add(w[i - 7])
            .wrapping_add(sigma1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (k, w) in K.iter().zip(w.iter()) {
        let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(big_sigma1)
            .wrapping_add(ch)
            .wrapping_add(*k)
            .wrapping_add(*w);
        let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_sigma0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

/// Hashes `len` bytes at `data` into `out` (32 bytes). `data` may be NULL if
/// `len` is 0. Does nothing if `out` is NULL, if `data` is NULL with `len` > 0,
/// or if `len` is larger than isize::MAX.
///
/// Locks: none. Never panics.
///
/// # Safety
/// If `data` is not NULL it must point to `len` readable bytes. `out` must be
/// NULL or point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_sha256_buf(data: *const u8, len: usize, out: *mut u8) {
    if out.is_null() || (data.is_null() && len > 0) || len > isize::MAX as usize {
        return;
    }
    let data: &[u8] = if len == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, len)
    };
    ptr::copy_nonoverlapping(digest(data).as_ptr(), out, DIGEST_LEN);
}

/// Hashes the file at `path` into `out` (32 bytes). With `skip_end`, the last
/// 32 bytes of the file are not hashed.
///
/// Returns 0 and writes `out` on success. Otherwise `out` is not written and
/// the result is EINVAL (positive) for a NULL argument, the errno of a failed
/// open (positive), or the errno of a failed read (negative).
///
/// Locks: none. Never panics.
///
/// # Safety
/// `path` must be NULL or a NUL-terminated string. `out` must be NULL or point
/// to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_sha256_file(
    path: *const c_char,
    skip_end: bool,
    out: *mut u8,
) -> c_int {
    if path.is_null() || out.is_null() {
        return EINVAL;
    }
    let path = Path::new(OsStr::from_bytes(CStr::from_ptr(path).to_bytes()));
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => return errno(&e),
    };
    match hash_reader(&mut file, skip_end) {
        Ok(digest) => {
            ptr::copy_nonoverlapping(digest.as_ptr(), out, DIGEST_LEN);
            0
        }
        Err(e) => -errno(&e),
    }
}

/// The errno of an I/O error, EIO if it has none
fn errno(e: &io::Error) -> c_int {
    e.raw_os_error().unwrap_or(EIO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::CString;
    use std::fs;
    use std::path::PathBuf;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The first `len` bytes of a fixed LCG stream
    fn lcg_bytes(len: usize) -> Vec<u8> {
        let mut x: u32 = 0x1234_5678;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect()
    }

    /// Writes `data` to a file named after this process and `name`
    fn temp_file(name: &str, data: &[u8]) -> PathBuf {
        let path = env::temp_dir().join(format!("ftl-rs-sha256-{}-{name}", std::process::id()));
        fs::write(&path, data).unwrap();
        path
    }

    /// ftl_rs_sha256_file() on `path`: Ok with the digest, or the raw return value
    fn call_file(path: &Path, skip_end: bool) -> Result<[u8; DIGEST_LEN], c_int> {
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let mut out = [0u8; DIGEST_LEN];
        match unsafe { ftl_rs_sha256_file(c_path.as_ptr(), skip_end, out.as_mut_ptr()) } {
            0 => Ok(out),
            rc => Err(rc),
        }
    }

    #[test]
    fn nist_vectors() {
        assert_eq!(
            hex(&digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 448-bit message: the padding needs a second block
        assert_eq!(
            hex(&digest(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // 896-bit message
        assert_eq!(
            hex(&digest(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
        assert_eq!(
            hex(&digest(&vec![b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn lengths_0_to_130_match_in_any_chunking() {
        let mut seed: u32 = 0x9e37_79b9;
        for len in 0..=130 {
            let data = lcg_bytes(len);
            let expected = digest(&data);

            // Fixed chunk sizes, one byte up to the whole message
            for chunk in 1..=len.max(1) {
                let mut hasher = Sha256::new();
                for piece in data.chunks(chunk) {
                    hasher.update(piece);
                }
                assert_eq!(hasher.finalize(), expected, "len {len}, chunk {chunk}");
            }

            // Random split points, including empty updates
            let mut hasher = Sha256::new();
            let mut rest = &data[..];
            while !rest.is_empty() {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let take = seed as usize % (rest.len() + 1);
                hasher.update(&rest[..take]);
                rest = &rest[take..];
            }
            hasher.update(&[]);
            assert_eq!(hasher.finalize(), expected, "len {len}, random chunks");
        }
    }

    #[test]
    fn buffer_export_matches_digest() {
        let mut out = [0u8; DIGEST_LEN];
        for len in [0, 1, 55, 56, 63, 64, 65, 4096, 65_536 + 1] {
            let data = lcg_bytes(len);
            unsafe { ftl_rs_sha256_buf(data.as_ptr(), data.len(), out.as_mut_ptr()) };
            assert_eq!(out, digest(&data), "len {len}");
        }
    }

    #[test]
    fn golden_fixture_sums() {
        // test/golden/expected/sha256/. lorem.txt is not in rust/, so its sum
        // is only checked by `golden --check sha256`
        assert_eq!(
            hex(&digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&digest(b"hello\n")),
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
        // binary.bin: byte i is (7 + 31 i) % 256 below 4096, then i % 256
        let binary: Vec<u8> = (0..4352usize)
            .map(|i| {
                if i < 4096 {
                    ((7 + 31 * i) % 256) as u8
                } else {
                    (i % 256) as u8
                }
            })
            .collect();
        assert_eq!(
            hex(&digest(&binary)),
            "bec96d4b0bfd66c9a0d3948f785b79b2802a81084ebf621a3546e00b705d5d1f"
        );
        let path = temp_file("binary", &binary);
        let sum = call_file(&path, false).unwrap();
        fs::remove_file(&path).unwrap();
        assert_eq!(
            hex(&sum),
            "bec96d4b0bfd66c9a0d3948f785b79b2802a81084ebf621a3546e00b705d5d1f"
        );
    }

    #[test]
    fn skip_end_leaves_out_the_last_32_bytes() {
        // Around 0, 32 and the 64 KiB read size
        let lengths = [
            0, 1, 31, 32, 33, 64, 100, 65_535, 65_536, 65_537, 65_568, 65_569, 131_103,
        ];
        for len in lengths {
            let data = lcg_bytes(len);
            let path = temp_file(&format!("skip-{len}"), &data);
            let kept = len.saturating_sub(DIGEST_LEN);
            assert_eq!(
                call_file(&path, true),
                Ok(digest(&data[..kept])),
                "len {len}, skip_end"
            );
            assert_eq!(call_file(&path, false), Ok(digest(&data)), "len {len}");
            fs::remove_file(&path).unwrap();
        }
    }

    #[test]
    fn directory_is_a_read_error() {
        let dir = env::temp_dir();
        let errno = fs::read(&dir).unwrap_err().raw_os_error().unwrap();
        assert_eq!(call_file(&dir, false), Err(-errno));
        assert_eq!(call_file(&dir, true), Err(-errno));
    }

    #[test]
    fn missing_file_is_an_open_error() {
        let missing = env::temp_dir().join("ftl-rs-sha256-no-such-file");
        let errno = fs::File::open(&missing)
            .unwrap_err()
            .raw_os_error()
            .unwrap();
        assert_eq!(call_file(&missing, false), Err(errno));
    }

    #[test]
    fn null_arguments_do_not_crash() {
        let mut out = [7u8; DIGEST_LEN];
        assert_eq!(
            unsafe { ftl_rs_sha256_file(ptr::null(), false, out.as_mut_ptr()) },
            EINVAL
        );
        let path = CString::new("/does/not/matter").unwrap();
        assert_eq!(
            unsafe { ftl_rs_sha256_file(path.as_ptr(), true, ptr::null_mut()) },
            EINVAL
        );

        // NULL data is the empty message when len is 0
        unsafe { ftl_rs_sha256_buf(ptr::null(), 0, out.as_mut_ptr()) };
        assert_eq!(out, digest(b""));

        // Other NULL combinations leave out alone
        out = [7u8; DIGEST_LEN];
        unsafe { ftl_rs_sha256_buf(ptr::null(), 5, out.as_mut_ptr()) };
        assert_eq!(out, [7u8; DIGEST_LEN]);
        unsafe { ftl_rs_sha256_buf(b"abc".as_ptr(), 3, ptr::null_mut()) };
    }
}
