// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! The code point and label rules of libidn2 2.3.8 (lib/idna.c, lib/context.c
//! and lib/bidi.c) on the tables of tables.rs. tr46_label() is the TR46 check
//! of a label of the mapped domain (libidn2 _tr46), u_label() the check of a
//! label before it is encoded (libidn2 label()).

use std::cmp::Ordering;

use idna_adapter::{
    Adapter, FIRST_BC_MASK, LAST_LTR_MASK, LAST_RTL_MASK, LEFT_OR_DUAL_JOINING_MASK,
    MIDDLE_LTR_MASK, MIDDLE_RTL_MASK, RIGHT_OR_DUAL_JOINING_MASK, RTL_MASK,
};

use super::tables::{Idna2008, IDNA2008, STD3, TR46_KEPT, TR46_VALID};
use super::IdnError;

const HYPHEN: u32 = 0x2D;
const ZWNJ: u32 = 0x200C;

/// The IDNA2008 property of `cp`, or None if the code point is unassigned.
pub fn idna2008(cp: u32) -> Option<Idna2008> {
    IDNA2008
        .binary_search_by(|&(lo, hi, _)| range_order(lo, hi, cp))
        .ok()
        .map(|i| IDNA2008[i].2)
}

/// Whether `cp` is an STD3 code point TR46 keeps when STD3 rules are off
/// (disallowed_STD3_valid or disallowed_STD3_mapped).
fn is_std3(cp: u32) -> bool {
    STD3.binary_search_by(|&(lo, hi)| range_order(lo, hi, cp))
        .is_ok()
}

/// Whether `cp` is in one of the sorted (first, last) ranges
fn in_ranges(ranges: &[(u32, u32)], cp: u32) -> bool {
    ranges
        .binary_search_by(|&(lo, hi)| range_order(lo, hi, cp))
        .is_ok()
}

/// Whether TR46 keeps `cp` in a mapped domain, that is, does not give it the
/// status disallowed (libidn2 _tr46 rejects the others, unlisted ones too)
pub fn tr46_kept(cp: u32) -> bool {
    in_ranges(TR46_KEPT, cp)
}

fn range_order(lo: u32, hi: u32, cp: u32) -> Ordering {
    if hi < cp {
        Ordering::Less
    } else if lo > cp {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// TR46 "valid" in non-transitional mode with STD3 allowed: the status valid
/// or deviation, and the STD3 code points.
fn tr46_valid(cp: u32) -> bool {
    in_ranges(TR46_VALID, cp) || is_std3(cp)
}

fn character(cp: u32) -> Option<char> {
    char::from_u32(cp)
}

fn has_two_hyphen(label: &[u32]) -> bool {
    label.len() >= 4 && label[2] == HYPHEN && label[3] == HYPHEN
}

fn leading_mark(adapter: &Adapter, label: &[u32]) -> bool {
    label
        .first()
        .and_then(|&cp| character(cp))
        .is_some_and(|c| adapter.is_mark(c))
}

/// libidn2 checks NFC on decoded labels. A label of characters with the TR46
/// status valid or deviation is NFC exactly when the TR46 mapping (which
/// normalizes) returns it unchanged. Labels with other characters are not
/// checked here; they fail the TR46 test anyway.
fn is_nfc(adapter: &Adapter, label: &[u32]) -> bool {
    let chars: Option<Vec<char>> = label
        .iter()
        .map(|&cp| if in_ranges(TR46_VALID, cp) { character(cp) } else { None })
        .collect();
    match chars {
        Some(chars) => adapter
            .map_normalize(chars.iter().copied())
            .eq(chars.iter().copied()),
        None => true,
    }
}

/// The TR46 tests of libidn2 (_tr46) for one label of the mapped domain, in
/// libidn2's order. `decoded` is set for a label that was an A-label.
pub fn tr46_label(adapter: &Adapter, label: &[u32], decoded: bool) -> Result<(), IdnError> {
    if decoded && !is_nfc(adapter, label) {
        return Err(IdnError::NotNfc);
    }
    if has_two_hyphen(label) {
        return Err(IdnError::TwoHyphen);
    }
    if label.first() == Some(&HYPHEN) || label.last() == Some(&HYPHEN) {
        return Err(IdnError::HyphenStartEnd);
    }
    if leading_mark(adapter, label) {
        return Err(IdnError::LeadingCombining);
    }
    if label.iter().any(|&cp| !tr46_valid(cp)) {
        return Err(IdnError::InvalidNonTransitional);
    }
    Ok(())
}

/// The tests of libidn2 (label(), non-transitional) for a label that is not
/// plain ASCII, or that is an A-label decoded to one.
pub fn u_label(adapter: &Adapter, label: &[u32]) -> Result<(), IdnError> {
    if has_two_hyphen(label) {
        return Err(IdnError::TwoHyphen);
    }
    if leading_mark(adapter, label) {
        return Err(IdnError::LeadingCombining);
    }
    // STD3 code points are exempt from the IDNA2008 test
    if label
        .iter()
        .any(|&cp| idna2008(cp) == Some(Idna2008::Disallowed) && !is_std3(cp))
    {
        return Err(IdnError::Disallowed);
    }
    for pos in 0..label.len() {
        contextj_rule(adapter, label, pos)?;
    }
    if label
        .iter()
        .any(|&cp| idna2008(cp) == Some(Idna2008::ContextO) && !contexto_with_rule(cp))
    {
        return Err(IdnError::ContextONoRule);
    }
    if label.iter().any(|&cp| idna2008(cp).is_none()) {
        return Err(IdnError::Unassigned);
    }
    bidi_ok(adapter, label)?;
    if label.iter().any(|&cp| !tr46_valid(cp)) {
        return Err(IdnError::InvalidNonTransitional);
    }
    Ok(())
}

/// The CONTEXTO characters that libidn2 has a rule for (context.c). libidn2
/// checks only that a rule exists, not the rule itself.
fn contexto_with_rule(cp: u32) -> bool {
    matches!(
        cp,
        0x00B7
            | 0x0375
            | 0x05F3
            | 0x05F4
            | 0x0660..=0x0669
            | 0x06F0..=0x06F9
            | 0x30FB
    )
}

fn is_virama(adapter: &Adapter, cp: u32) -> bool {
    character(cp).is_some_and(|c| adapter.is_virama(c))
}

fn is_left_or_dual(adapter: &Adapter, cp: u32) -> bool {
    character(cp).is_some_and(|c| {
        adapter
            .joining_type(c)
            .to_mask()
            .intersects(LEFT_OR_DUAL_JOINING_MASK)
    })
}

fn is_right_or_dual(adapter: &Adapter, cp: u32) -> bool {
    character(cp).is_some_and(|c| {
        adapter
            .joining_type(c)
            .to_mask()
            .intersects(RIGHT_OR_DUAL_JOINING_MASK)
    })
}

fn is_transparent(adapter: &Adapter, cp: u32) -> bool {
    character(cp).is_some_and(|c| adapter.joining_type(c).is_transparent())
}

/// The CONTEXTJ rule for the code point at `pos` (libidn2 _idn2_contextj_rule)
fn contextj_rule(adapter: &Adapter, label: &[u32], pos: usize) -> Result<(), IdnError> {
    let cp = label[pos];
    if idna2008(cp) != Some(Idna2008::ContextJ) {
        return Ok(());
    }
    if pos > 0 && is_virama(adapter, label[pos - 1]) {
        return Ok(());
    }
    // Without a virama before it, only a ZERO WIDTH NON-JOINER can pass
    if cp == ZWNJ {
        zwnj_joining_rule(adapter, label, pos)
    } else {
        Err(IdnError::ContextJ)
    }
}

/// The joining rule for a ZERO WIDTH NON-JOINER: a left or dual joining
/// character before it and a right or dual joining one after it, with only
/// transparent characters between.
fn zwnj_joining_rule(adapter: &Adapter, label: &[u32], pos: usize) -> Result<(), IdnError> {
    if pos == 0 || pos == label.len() - 1 {
        return Err(IdnError::ContextJ);
    }
    let mut before = pos - 1;
    loop {
        if is_left_or_dual(adapter, label[before]) {
            break;
        }
        if before == 0 || !is_transparent(adapter, label[before]) {
            return Err(IdnError::ContextJ);
        }
        before -= 1;
    }
    let mut after = pos + 1;
    loop {
        if is_right_or_dual(adapter, label[after]) {
            return Ok(());
        }
        if after == label.len() - 1 || !is_transparent(adapter, label[after]) {
            return Err(IdnError::ContextJ);
        }
        after += 1;
    }
}

/// The bidi rule of libidn2 (_idn2_bidi) for a label with a right-to-left
/// character. It checks each character after the first, as libidn2 does, not
/// the RFC 5893 masks alone.
fn bidi_ok(adapter: &Adapter, label: &[u32]) -> Result<(), IdnError> {
    let class = |cp: u32| character(cp).map(|c| adapter.bidi_class(c));
    let has_rtl = label
        .iter()
        .any(|&cp| class(cp).is_some_and(|bc| bc.to_mask().intersects(RTL_MASK)));
    if !has_rtl {
        return Ok(());
    }
    let first = class(label[0]).ok_or(IdnError::Bidi)?;
    let (middle, last) = if first.is_ltr() {
        (MIDDLE_LTR_MASK, LAST_LTR_MASK)
    } else if first.to_mask().intersects(FIRST_BC_MASK) {
        (MIDDLE_RTL_MASK, LAST_RTL_MASK)
    } else {
        return Err(IdnError::Bidi);
    };
    let mut end_ok = true;
    for &cp in &label[1..] {
        let bc = class(cp).ok_or(IdnError::Bidi)?;
        if !bc.to_mask().intersects(middle) {
            return Err(IdnError::Bidi);
        }
        end_ok = bc.to_mask().intersects(last) || bc.is_nonspacing_mark();
    }
    if end_ok {
        Ok(())
    } else {
        Err(IdnError::Bidi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cps(text: &str) -> Vec<u32> {
        text.chars().map(u32::from).collect()
    }

    #[test]
    fn idna2008_lookup_uses_inclusive_ranges() {
        assert_eq!(idna2008(0x61), Some(Idna2008::PValid));
        assert_eq!(idna2008(0x7A), Some(Idna2008::PValid));
        assert_eq!(idna2008(0x41), Some(Idna2008::Disallowed));
        assert_eq!(idna2008(0x200C), Some(Idna2008::ContextJ));
        assert_eq!(idna2008(0x378), None);
        assert!(is_std3(0x5F));
        assert!(!is_std3(0x61));
    }

    #[test]
    fn tr46_label_rules() {
        let adapter = Adapter::new();
        assert_eq!(tr46_label(&adapter, &cps("ab--c"), false), Err(IdnError::TwoHyphen));
        assert_eq!(tr46_label(&adapter, &cps("-ab"), false), Err(IdnError::HyphenStartEnd));
        assert_eq!(tr46_label(&adapter, &cps("\u{301}a"), false), Err(IdnError::LeadingCombining));
        assert_eq!(tr46_label(&adapter, &cps("a_b"), false), Ok(()));
        // Valid for TR46 (15.1), so the label stage decides (IDNA2008: DISALLOWED)
        assert_eq!(tr46_label(&adapter, &[0x1F600], false), Ok(()));
        assert_eq!(u_label(&adapter, &[0x1F600]), Err(IdnError::Disallowed));
    }

    #[test]
    fn contextj_needs_a_joining_neighbour() {
        let adapter = Adapter::new();
        assert_eq!(u_label(&adapter, &cps("a\u{200c}b")), Err(IdnError::ContextJ));
        assert_eq!(u_label(&adapter, &cps("\u{200d}")), Err(IdnError::ContextJ));
        // A virama before ZWJ or ZWNJ is accepted
        assert_eq!(u_label(&adapter, &cps("\u{915}\u{94d}\u{200d}\u{915}")), Ok(()));
    }

    #[test]
    fn bidi_rules() {
        let adapter = Adapter::new();
        assert_eq!(u_label(&adapter, &cps("a\u{5d0}")), Err(IdnError::Bidi));
        assert_eq!(u_label(&adapter, &cps("\u{5d0}\u{5d1}")), Ok(()));
        // A single right-to-left letter is allowed
        assert_eq!(u_label(&adapter, &cps("\u{5d0}")), Ok(()));
    }
}
