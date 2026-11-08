/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  C declarations of the Rust static library (rust/)
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */
#ifndef FTL_RS_H
#define FTL_RS_H

#include <stdint.h>

// Must match ABI_VERSION in rust/src/lib.rs
#define FTL_RS_ABI_VERSION 1u

#ifdef HAVE_FTL_RS
uint32_t ftl_rs_abi_version(void);
const char *ftl_rs_version(void);
#endif

#endif // FTL_RS_H
