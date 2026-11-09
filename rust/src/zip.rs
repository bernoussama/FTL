// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! ZIP archive reader and writer for the teleporter (in memory). Phase 3
//! module: replaces the miniz mz_zip_* calls in src/zip/teleporter.c. Parses
//! untrusted uploads.
