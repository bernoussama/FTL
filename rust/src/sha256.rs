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
