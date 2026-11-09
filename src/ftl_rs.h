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
#include <stdbool.h>
// SHA-256 of a buffer into out. data may be NULL if len is 0. Does nothing if
// out is NULL, or data is NULL with len > 0.
void ftl_rs_sha256_buf(const uint8_t *data, size_t len, uint8_t out[32]);
// SHA-256 of a file into out, without its last 32 bytes if skip_end. Returns 0
// on success. Otherwise out is not written, and the result is EINVAL for a NULL
// argument, the errno of a failed open (positive) or of a failed read (negative).
int ftl_rs_sha256_file(const char *path, bool skip_end, uint8_t out[32]);
// -- end sha256

// Phase 2: idn2 (rust/src/idn.rs)
// Converts a UTF-8 domain name to ASCII (as idn2_to_ascii_8z() with
// IDN2_NONTRANSITIONAL) or to Unicode (as idn2_to_unicode_8z8z()). On success
// writes the NUL-terminated result to *out, to be released with
// ftl_rs_buf_free(), and returns 0. Otherwise returns the libidn2 error code
// (IDN2_*, see ftl_rs_idn2_strerror()) and leaves *out alone. input must be a
// NUL-terminated string. NULL arguments give -200 (IDN2_ENCODING_ERROR).
int ftl_rs_idn2_to_ascii(const char *input, ftl_rs_buf *out);
int ftl_rs_idn2_to_unicode(const char *input, ftl_rs_buf *out);
// The message for an error code, as idn2_strerror() gives it. Static, not freed.
const char *ftl_rs_idn2_strerror(int code);
// -- end idn2

// Phase 2: --complete (rust/src/complete.rs)
// A config item for ftl_rs_complete(). The strings are borrowed for the call.
// kind says how the item is completed:
#define FTL_RS_CONF_NONE       0u // nothing to suggest
#define FTL_RS_CONF_BOOL       1u // true and false, matched ignoring case
#define FTL_RS_CONF_VALUE      2u // default_value, if it starts with the word
#define FTL_RS_CONF_JSON_ARRAY 3u // default_value quoted for the shell, if it starts with the word
#define FTL_RS_CONF_CHOICES    4u // choices, matched ignoring case
#define FTL_RS_CONF_ALWAYS     5u // default_value, whatever the word
typedef struct ftl_rs_conf_entry {
	const char *key;            // config key, e.g. "dns.port"
	uint32_t kind;              // FTL_RS_CONF_*
	const char *default_value;  // NULL if there is none
	const char *const *choices; // the names, for FTL_RS_CONF_CHOICES
	size_t n_choices;
} ftl_rs_conf_entry;

_Static_assert(sizeof(ftl_rs_conf_entry) == 5 * sizeof(void *),
               "ftl_rs_conf_entry: size differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_conf_entry, key) == 0,
               "ftl_rs_conf_entry: key offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_conf_entry, kind) == sizeof(void *),
               "ftl_rs_conf_entry: kind offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_conf_entry, default_value) == 2 * sizeof(void *),
               "ftl_rs_conf_entry: default_value offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_conf_entry, choices) == 3 * sizeof(void *),
               "ftl_rs_conf_entry: choices offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_conf_entry, n_choices) == 4 * sizeof(void *),
               "ftl_rs_conf_entry: n_choices offset differs from the Rust layout");

// The lines `pihole-FTL --complete` prints for argv (argc strings). entries holds
// the config items for --config, otherwise pass NULL and 0. The result is freed
// with ftl_rs_buf_free().
ftl_rs_buf ftl_rs_complete(int argc, const char *const *argv, const ftl_rs_conf_entry *entries, size_t n_entries);
// Size and field offsets of ftl_rs_conf_entry, out[6], as the Rust side sees them
void ftl_rs_conf_entry_layout(size_t out[6]);
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
