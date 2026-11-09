// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! gzip (RFC 1952) compression and decompression on top of miniz_oxide.
//! Phase 3 module: replaces src/zip/gzip.c. Parses untrusted uploads.
