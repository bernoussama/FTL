// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Punycode (RFC 3492) as libidn2 2.3.8 implements it (lib/punycode.c): the
//! same limits and error codes, so that A-label conversion fails in the same
//! cases.

use super::IdnError;

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;
const DELIMITER: u8 = b'-';

/// Decodes `input`, the part of an A-label after "xn--", to at most `max_out`
/// code points. The input may hold only ASCII letters, digits, '-' and '_'.
/// The result can contain low surrogates, which are not text.
pub fn decode(input: &[u8], max_out: usize) -> Result<Vec<u32>, IdnError> {
    if input.is_empty() {
        return Err(IdnError::PunycodeBadInput);
    }
    // The basic code points end at the last delimiter
    let mut b = 0;
    for (j, &c) in input.iter().enumerate() {
        if !is_basic(c) {
            return Err(IdnError::PunycodeBadInput);
        }
        if c == DELIMITER {
            b = j;
        }
    }
    let mut out: Vec<u32> = Vec::new();
    if input[b] == DELIMITER {
        if b == 0 || b == input.len() - 1 {
            return Err(IdnError::PunycodeBadInput);
        }
        if b >= max_out {
            return Err(IdnError::PunycodeBigOutput);
        }
        out.extend(input[..b].iter().map(|&c| u32::from(c)));
        b += 1;
    }

    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut pos = b;
    while pos < input.len() {
        let oldi = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let Some(&c) = input.get(pos) else {
                return Err(IdnError::PunycodeBadInput);
            };
            pos += 1;
            let digit = decode_digit(c);
            if digit >= BASE {
                return Err(IdnError::PunycodeBadInput);
            }
            if digit > (u32::MAX - i) / w {
                return Err(IdnError::PunycodeOverflow);
            }
            i += digit * w;
            let t = threshold(k, bias);
            if digit < t {
                break;
            }
            if w > u32::MAX / (BASE - t) {
                return Err(IdnError::PunycodeOverflow);
            }
            w *= BASE - t;
            k += BASE;
        }
        let points = out.len() as u32 + 1;
        bias = adapt(i - oldi, points, oldi == 0);
        if i / points > u32::MAX - n {
            return Err(IdnError::PunycodeOverflow);
        }
        n += i / points;
        if n > 0x10FFFF || (0xD800..=0xDBFF).contains(&n) {
            return Err(IdnError::PunycodeBadInput);
        }
        i %= points;
        if out.len() >= max_out {
            return Err(IdnError::PunycodeBigOutput);
        }
        out.insert(i as usize, n);
        i += 1;
    }
    Ok(out)
}

/// Encodes the code points `input` as punycode, without the "xn--" prefix. The
/// result is at most `max_out` bytes long, or PunycodeBigOutput.
pub fn encode(input: &[u32], max_out: usize) -> Result<String, IdnError> {
    let mut out: Vec<u8> = Vec::new();
    for &c in input {
        if c < 0x80 {
            // Room for this code point and the delimiter that may follow
            if out.len() + 2 > max_out {
                return Err(IdnError::PunycodeBigOutput);
            }
            out.push(c as u8);
        } else if c > 0x10FFFF || (0xD800..=0xDBFF).contains(&c) {
            return Err(IdnError::PunycodeBadInput);
        }
    }

    let basic = out.len();
    let mut h = basic;
    if basic > 0 {
        out.push(DELIMITER);
    }
    let mut n = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    while h < input.len() {
        // The smallest code point that is not below n
        let m = input
            .iter()
            .copied()
            .filter(|&c| c >= n)
            .min()
            .unwrap_or(u32::MAX);
        let h32 = h as u32;
        if m - n > (u32::MAX - delta) / (h32 + 1) {
            return Err(IdnError::PunycodeOverflow);
        }
        delta += (m - n) * (h32 + 1);
        n = m;
        for &c in input {
            if c < n {
                delta = delta.checked_add(1).ok_or(IdnError::PunycodeOverflow)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    if out.len() >= max_out {
                        return Err(IdnError::PunycodeBigOutput);
                    }
                    let t = threshold(k, bias);
                    if q < t {
                        break;
                    }
                    out.push(encode_digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(encode_digit(q));
                bias = adapt(delta, h32 + 1, h == basic);
                delta = 0;
                h += 1;
            }
        }
        delta = delta.wrapping_add(1);
        n = n.wrapping_add(1);
    }
    // Only ASCII bytes are pushed
    Ok(out.into_iter().map(char::from).collect())
}

/// Whether `c` may appear in the input of decode()
fn is_basic(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == DELIMITER || c == b'_'
}

/// The digit value of `c`. Bytes that are not digits or letters count as 0,
/// as in libidn2 (so '_' is 0).
fn decode_digit(c: u8) -> u32 {
    match c {
        b'a'..=b'z' => u32::from(c - b'a'),
        b'A'..=b'Z' => u32::from(c - b'A'),
        b'0'..=b'9' => u32::from(c - b'0') + 26,
        _ => 0,
    }
}

/// The basic code point for digit `d` (0..36): 'a'..='z' for 0..26, '0'..='9' after
fn encode_digit(d: u32) -> u8 {
    (d + 22 + 75 * u32::from(d < 26)) as u8
}

/// The weight of the next digit (RFC 3492 section 5)
fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        TMIN
    } else if k >= bias + TMAX {
        TMAX
    } else {
        k - bias
    }
}

/// The new bias after a delta (RFC 3492 section 6.1)
fn adapt(delta: u32, numpoints: u32, first_time: bool) -> u32 {
    let mut delta = if first_time { delta / DAMP } else { delta >> 1 };
    delta = delta.wrapping_add(delta / numpoints);
    let mut k = 0;
    while delta > ((BASE - TMIN) * TMAX) / 2 {
        delta /= BASE - TMIN;
        k += BASE;
    }
    k + ((BASE - TMIN + 1) * delta) / (delta + SKEW)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code_points(text: &str) -> Vec<u32> {
        text.chars().map(u32::from).collect()
    }

    #[test]
    fn encodes_and_decodes_the_known_labels() {
        assert_eq!(encode(&code_points("münchen"), 59).unwrap(), "mnchen-3ya");
        assert_eq!(decode(b"mnchen-3ya", 63).unwrap(), code_points("münchen"));
        // Digits are case-insensitive, the basic part is copied as it is
        assert_eq!(decode(b"mnchen-3YA", 63).unwrap(), code_points("münchen"));
        assert_eq!(encode(&code_points("abc"), 59).unwrap(), "abc-");
        // A trailing delimiter is never accepted
        assert_eq!(decode(b"abc-", 63), Err(IdnError::PunycodeBadInput));
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [&b""[..], b"zz", b"a-", b"-a", "ä".as_bytes(), b"a_\x7f"] {
            assert_eq!(decode(bad, 63), Err(IdnError::PunycodeBadInput), "{bad:?}");
        }
    }

    #[test]
    fn output_limits_apply() {
        assert_eq!(encode(&[0xe4; 70], 59), Err(IdnError::PunycodeBigOutput));
        // Three code points do not fit in a decode of two
        let long = encode(&[0x4e00; 3], 59).unwrap();
        assert_eq!(decode(long.as_bytes(), 2), Err(IdnError::PunycodeBigOutput));
    }

    #[test]
    fn rejects_surrogates_and_values_above_unicode() {
        assert_eq!(encode(&[0xD800, 0x41], 59), Err(IdnError::PunycodeBadInput));
        assert_eq!(encode(&[0x110000], 59), Err(IdnError::PunycodeBadInput));
    }
}
