// Copyright 2013-2014 The rust-url developers.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This crate is not meant to be used directly. It part of the unicode-rs back end
//! for the `idna` crate providing the UTS 46 mapping data and an abstraction over
//! JoiningType data (delegated to `unicode-joining-type`).
//!
//! See the [README of the latest version of the `idna_adapter` crate][1] for
//! how to use.
//!
//! [1]: https://docs.rs/crate/idna_adapter/latest

// The code in this file has been moved from the `rust-url` repo.
// See https://github.com/servo/rust-url/blob/c04aca3f74eb567ec4853362ef28b7ce2f19c5d3/idna/src/uts46.rs
// for older history.

#![no_std]

use self::Mapping::*;

include!("uts46_mapping_table.rs");

#[derive(Debug)]
struct StringTableSlice {
    // Store these as separate fields so the structure will have an
    // alignment of 1 and thus pack better into the Mapping enum, below.
    byte_start_lo: u8,
    byte_start_hi: u8,
    byte_len: u8,
}

fn decode_slice(slice: &StringTableSlice) -> &'static str {
    let lo = slice.byte_start_lo as usize;
    let hi = slice.byte_start_hi as usize;
    let start = (hi << 8) | lo;
    let len = slice.byte_len as usize;
    &STRING_TABLE[start..(start + len)]
}

#[repr(u8)]
#[derive(Debug)]
enum Mapping {
    Valid,
    Ignored,
    Mapped(StringTableSlice),
    Disallowed,
}

fn find_char(codepoint: char) -> &'static Mapping {
    let idx = match TABLE.binary_search_by_key(&codepoint, |&val| val.0) {
        Ok(idx) => idx,
        Err(idx) => idx - 1,
    };

    const SINGLE_MARKER: u16 = 1 << 15;

    let (base, x) = TABLE[idx];
    let single = (x & SINGLE_MARKER) != 0;
    let offset = !SINGLE_MARKER & x;

    if single {
        &MAPPING_TABLE[offset as usize]
    } else {
        &MAPPING_TABLE[(offset + (codepoint as u16 - base as u16)) as usize]
    }
}

pub struct Mapper<I>
where
    I: Iterator<Item = char>,
{
    chars: I,
    slice: Option<core::str::Chars<'static>>,
    ignored_as_errors: bool,
}

impl<I> Mapper<I>
where
    I: Iterator<Item = char>,
{
    pub fn new(delegate: I, ignored_as_errors: bool) -> Self {
        Mapper {
            chars: delegate,
            slice: None,
            ignored_as_errors,
        }
    }
}

impl<I> Iterator for Mapper<I>
where
    I: Iterator<Item = char>,
{
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(s) = &mut self.slice {
                match s.next() {
                    Some(c) => return Some(c),
                    None => {
                        self.slice = None;
                    }
                }
            }

            let codepoint = self.chars.next()?;
            if let '.' | '-' | 'a'..='z' | '0'..='9' = codepoint {
                return Some(codepoint);
            }

            return Some(match *find_char(codepoint) {
                Mapping::Valid => codepoint,
                Mapping::Ignored => {
                    if self.ignored_as_errors {
                        '\u{FFFD}'
                    } else {
                        continue;
                    }
                }
                Mapping::Mapped(ref slice) => {
                    self.slice = Some(decode_slice(slice).chars());
                    continue;
                }
                Mapping::Disallowed => '\u{FFFD}',
            });
        }
    }
}

// Pushing the JoiningType functionality from `idna_adapter` to this crate
// insulates `idna_adapter` from future semver breaks of `unicode_joining_type`.

/// Turns a joining type into a mask for comparing with multiple type at once.
const fn joining_type_to_mask(jt: unicode_joining_type::JoiningType) -> u32 {
    1u32 << (jt as u32)
}

/// Mask for checking for both left and dual joining.
pub const LEFT_OR_DUAL_JOINING_MASK: JoiningTypeMask = JoiningTypeMask(
    joining_type_to_mask(unicode_joining_type::JoiningType::LeftJoining)
        | joining_type_to_mask(unicode_joining_type::JoiningType::DualJoining),
);

/// Mask for checking for both left and dual joining.
pub const RIGHT_OR_DUAL_JOINING_MASK: JoiningTypeMask = JoiningTypeMask(
    joining_type_to_mask(unicode_joining_type::JoiningType::RightJoining)
        | joining_type_to_mask(unicode_joining_type::JoiningType::DualJoining),
);

/// Value for the Joining_Type Unicode property.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct JoiningType(unicode_joining_type::JoiningType);

impl JoiningType {
    /// Returns the corresponding `JoiningTypeMask`.
    #[inline(always)]
    pub fn to_mask(self) -> JoiningTypeMask {
        JoiningTypeMask(joining_type_to_mask(self.0))
    }

    // `true` iff this value is the Transparent value.
    #[inline(always)]
    pub fn is_transparent(self) -> bool {
        self.0 == unicode_joining_type::JoiningType::Transparent
    }
}

/// A mask representing potentially multiple `JoiningType`
/// values.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct JoiningTypeMask(u32);

impl JoiningTypeMask {
    /// `true` iff both masks have at `JoiningType` in common.
    #[inline(always)]
    pub fn intersects(self, other: JoiningTypeMask) -> bool {
        self.0 & other.0 != 0
    }
}

/// Returns the Joining_Type of `c`.
#[inline(always)]
pub fn joining_type(c: char) -> JoiningType {
    JoiningType(unicode_joining_type::get_joining_type(c))
}

#[cfg(test)]
mod tests {
    use super::{find_char, Mapping};
    use assert_matches::assert_matches;

    #[test]
    fn mapping_fast_path() {
        assert_matches!(find_char('-'), &Mapping::Valid);
        assert_matches!(find_char('.'), &Mapping::Valid);
        for c in &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] {
            assert_matches!(find_char(*c), &Mapping::Valid);
        }
        for c in &[
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
            'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        ] {
            assert_matches!(find_char(*c), &Mapping::Valid);
        }
    }
}
