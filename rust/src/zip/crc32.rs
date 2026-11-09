// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! CRC-32 (IEEE 802.3, the reflected polynomial 0xEDB88320) of ZIP members.

/// The table of byte-wise CRCs, built at compile time
const TABLE: [u32; 256] = make_table();

const fn make_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

/// Continues a CRC over more data. `crc` is 0 for the first piece.
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &byte in data {
        c = TABLE[((c ^ u32::from(byte)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// The CRC-32 of `data`
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

/// A CRC-32 over data that arrives in pieces
#[derive(Default)]
pub struct Crc32(u32);

impl Crc32 {
    pub fn update(&mut self, data: &[u8]) {
        self.0 = crc32_update(self.0, data);
    }

    pub fn finish(&self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_value_and_empty_input() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }

    #[test]
    fn pieces_give_the_same_crc() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut streamed = Crc32::default();
        for piece in data.chunks(37) {
            streamed.update(piece);
        }
        assert_eq!(streamed.finish(), crc32(&data));
    }
}
