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

#include <stddef.h>
#include <stdint.h>

// Must match ABI_VERSION in rust/src/lib.rs
#define FTL_RS_ABI_VERSION 3u

#ifdef HAVE_FTL_RS
// Byte buffer that Rust allocates (rust/src/buf.rs). Release it with
// ftl_rs_buf_free(), never with free(). `pihole-FTL rust-version` checks the
// layout against the Rust side at runtime.
typedef struct ftl_rs_buf {
	uint8_t *ptr;
	size_t len;
	size_t cap;
} ftl_rs_buf;

_Static_assert(sizeof(ftl_rs_buf) == sizeof(void *) + 2 * sizeof(size_t),
               "ftl_rs_buf: size differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_buf, ptr) == 0,
               "ftl_rs_buf: ptr offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_buf, len) == sizeof(void *),
               "ftl_rs_buf: len offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_buf, cap) == sizeof(void *) + sizeof(size_t),
               "ftl_rs_buf: cap offset differs from the Rust layout");

uint32_t ftl_rs_abi_version(void);
const char *ftl_rs_version(void);
void ftl_rs_buf_layout(size_t out[4]);
void ftl_rs_buf_free(ftl_rs_buf *buf);
void ftl_rs_after_fork(void);

// Phase 2: sha256 (rust/src/sha256.rs)
// -- end sha256

// Phase 2: idn2 (rust/src/idn.rs)
// -- end idn2

// Phase 2: --complete (rust/src/complete.rs)
// -- end complete

// pihole-FTL rust-compare <module> [args]: runs the C and the Rust version of
// a module on the same inputs and reports differences (src/ftl_rs_compare*.c)
int ftl_rs_compare(int argc, char *argv[]);
int ftl_rs_compare_sha256(int argc, char *argv[]);
int ftl_rs_compare_idn2(int argc, char *argv[]);
int ftl_rs_compare_complete(int argc, char *argv[]);

// Test-only exports for the hidden rust-* subcommands (src/ftl_rs_selftest.c)
#define FTL_RS_FORK_TEST_MAX_CHILDREN 1000u
ftl_rs_buf ftl_rs_selftest_buf(size_t n);
uint64_t ftl_rs_selftest_tick(void);
void __attribute__((noreturn)) ftl_rs_selftest_panic(void);
int ftl_rs_fork_test(unsigned int children);
#endif

#endif // FTL_RS_H
