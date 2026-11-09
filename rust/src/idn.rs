// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! IDNA conversion for pihole-FTL idn2: UTS 46 non-transitional processing
//! (idna crate) plus the IDNA2008 code point rules libidn2 applies. Phase 2
//! module: replaces the libidn2 calls in src/args.c.
