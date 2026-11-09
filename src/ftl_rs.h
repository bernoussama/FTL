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
#define FTL_RS_ABI_VERSION 4u

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

// Phase 3: tar (rust/src/tar.rs)
// Finds the first entry named name in the tar archive of tar_size bytes at tar
// (NULL is an empty archive). On success returns true and writes the offset of
// the entry's data in tar to *payload_offset and its size to *file_size. Otherwise
// returns false and writes 0 to both. Each output may be NULL. name must be a
// NUL-terminated string (NULL matches nothing).
bool ftl_rs_tar_find(const uint8_t *tar, size_t tar_size, const char *name, size_t *payload_offset, size_t *file_size);
// The entries of the archive in order, as ftl_rs_tar_entry records. Free the
// result with ftl_rs_buf_free(). A NULL archive gives an empty result.
ftl_rs_buf ftl_rs_tar_list(const uint8_t *tar, size_t tar_size);
// One entry of ftl_rs_tar_list(): the offset of its header block in the archive
// (the name is the NUL-terminated string there) and the size of its data
typedef struct ftl_rs_tar_entry {
	size_t offset;
	size_t size;
} ftl_rs_tar_entry;

_Static_assert(sizeof(ftl_rs_tar_entry) == 2 * sizeof(size_t),
               "ftl_rs_tar_entry: size differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_tar_entry, offset) == 0,
               "ftl_rs_tar_entry: offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_tar_entry, size) == sizeof(size_t),
               "ftl_rs_tar_entry: size offset differs from the Rust layout");
// -- end tar

// Phase 3: gzip (rust/src/gzip.rs)
// Inflates the gzip stream of len bytes at data, with the checks and the messages
// of inflate_buffer(). On success returns true and writes the data to *out. On
// failure returns false, leaves *out alone and writes the log text of the error
// to *message (not NUL-terminated). Both are released with ftl_rs_buf_free().
// data may be NULL with len 0. Returns false, and writes nothing, if out or
// message is NULL, or data is NULL with len > 0.
bool ftl_rs_gzip_inflate(const uint8_t *data, size_t len, ftl_rs_buf *out, ftl_rs_buf *message);
// Deflates len bytes at data into a gzip stream (the header has mtime, in seconds
// since the epoch). Writes the stream to *out, released with ftl_rs_buf_free(). data
// may be NULL with len 0. Returns false, and writes nothing, if out is NULL, or data
// is NULL with len > 0.
bool ftl_rs_gzip_deflate(const uint8_t *data, size_t len, uint32_t mtime, ftl_rs_buf *out);
// -- end gzip

// Phase 3: zip (rust/src/zip.rs, rust/src/zip/)
// A ZIP archive read from memory, as miniz's mz_zip_reader does it (same checks,
// same order, same last-error state). The archive is borrowed and must stay
// unchanged until ftl_rs_zip_reader_free(). Errors are the mz_zip_error values
// of src/zip/miniz/miniz.h, so mz_zip_get_error_string() gives their text.
typedef struct ftl_rs_zip_reader ftl_rs_zip_reader;
// A ZIP archive written in memory, as miniz's mz_zip_writer does it
typedef struct ftl_rs_zip_writer ftl_rs_zip_writer;

// One member, as mz_zip_archive_file_stat. name and comment are NUL-terminated
// and cut to 511 bytes, as in miniz. The layout is checked below and in Rust.
typedef struct ftl_rs_zip_stat {
	uint16_t method;         // 0 (stored) or 8 (deflate)
	uint16_t bit_flag;
	uint16_t dos_time;
	uint16_t dos_date;
	uint32_t crc32;
	uint32_t external_attr;
	bool is_directory;
	uint8_t reserved[7];     // zero: keeps comp_size at 24 on every ABI (i386 aligns uint64_t to 4)
	uint64_t comp_size;
	uint64_t uncomp_size;
	uint64_t local_header_ofs;
	char name[512];
	char comment[512];
} ftl_rs_zip_stat;

_Static_assert(sizeof(ftl_rs_zip_stat) == 1072,
               "ftl_rs_zip_stat: size differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_zip_stat, is_directory) == 16,
               "ftl_rs_zip_stat: is_directory offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_zip_stat, reserved) == 17,
               "ftl_rs_zip_stat: reserved offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_zip_stat, comp_size) == 24,
               "ftl_rs_zip_stat: comp_size offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_zip_stat, local_header_ofs) == 40,
               "ftl_rs_zip_stat: local_header_ofs offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_zip_stat, name) == 48,
               "ftl_rs_zip_stat: name offset differs from the Rust layout");
_Static_assert(offsetof(ftl_rs_zip_stat, comment) == 560,
               "ftl_rs_zip_stat: comment offset differs from the Rust layout");

// Writes the size of ftl_rs_zip_stat and the offsets of is_directory, comp_size,
// local_header_ofs, name and comment as the Rust side sees them
void ftl_rs_zip_stat_layout(size_t out[6]);

// Opens the archive of len bytes at data (as mz_zip_reader_init_mem()). Returns 0
// and sets *reader on success, free it with ftl_rs_zip_reader_free(). Otherwise
// returns the error and sets *reader to NULL. data must not be NULL (then the
// error is INVALID_PARAMETER, as in miniz).
uint32_t ftl_rs_zip_open(const uint8_t *data, size_t len, ftl_rs_zip_reader **reader);
// Number of members (mz_zip_reader_get_num_files())
uint32_t ftl_rs_zip_num_files(const ftl_rs_zip_reader *reader);
// The stat of member index (mz_zip_reader_file_stat()). Returns false on error,
// with the error as ftl_rs_zip_last_error() gives it. A member that is an
// unsupported method or encrypted still gives true, and sets the last error.
bool ftl_rs_zip_file_stat(const ftl_rs_zip_reader *reader, uint32_t index, ftl_rs_zip_stat *stat);
// Writes the uncompressed data of member index into buf, which must hold at least
// the member's uncompressed size (mz_zip_reader_extract_to_mem()). The CRC is
// checked. Returns false on error. buf may be NULL only with buf_size 0.
bool ftl_rs_zip_extract(const ftl_rs_zip_reader *reader, uint32_t index, void *buf, size_t buf_size);
// Returns the last error and clears it (mz_zip_get_last_error()). 0 for NULL.
uint32_t ftl_rs_zip_last_error(const ftl_rs_zip_reader *reader);
// Frees a reader from ftl_rs_zip_open(). NULL is a no-op.
void ftl_rs_zip_reader_free(ftl_rs_zip_reader *reader);
// Checks every member of the archive (mz_zip_validate_mem_archive()). Returns 0
// if it is valid, otherwise the error.
uint32_t ftl_rs_zip_validate(const uint8_t *data, size_t len);

// Starts an empty archive (mz_zip_writer_init_heap()). Free it with
// ftl_rs_zip_writer_free(), also after ftl_rs_zip_writer_finish().
ftl_rs_zip_writer *ftl_rs_zip_writer_new(void);
// Adds a member with the data (len bytes, data may be NULL with len 0), the name
// and the comment (both NUL-terminated, comment may be NULL). dos_time and
// dos_date are the last-modified time in MS-DOS format. Members of 3 bytes or
// less are stored, the others deflated at level 9. Returns 0, or the error. On
// error the archive is unchanged, so the member is not in it.
uint32_t ftl_rs_zip_writer_add(ftl_rs_zip_writer *writer, const char *name, const uint8_t *data, size_t len, const char *comment, uint16_t dos_time, uint16_t dos_date);
// Writes the archive into out, which is released with ftl_rs_buf_free(). Returns 0,
// or the error, and then out is not written. No member can be added afterwards.
uint32_t ftl_rs_zip_writer_finish(ftl_rs_zip_writer *writer, ftl_rs_buf *out);
// Frees a writer from ftl_rs_zip_writer_new(). NULL is a no-op.
void ftl_rs_zip_writer_free(ftl_rs_zip_writer *writer);
// -- end zip

// pihole-FTL rust-compare <module> [args]: runs the C and the Rust version of
// a module on the same inputs and reports differences (src/ftl_rs_compare*.c)
int ftl_rs_compare(int argc, char *argv[]);
int ftl_rs_compare_sha256(int argc, char *argv[]);
int ftl_rs_compare_idn2(int argc, char *argv[]);
int ftl_rs_compare_complete(int argc, char *argv[]);
int ftl_rs_compare_tar(int argc, char *argv[]);
int ftl_rs_compare_gzip(int argc, char *argv[]);
int ftl_rs_compare_zip(int argc, char *argv[]);

// Test-only exports for the hidden rust-* subcommands (src/ftl_rs_selftest.c)
#define FTL_RS_FORK_TEST_MAX_CHILDREN 1000u
ftl_rs_buf ftl_rs_selftest_buf(size_t n);
uint64_t ftl_rs_selftest_tick(void);
void __attribute__((noreturn)) ftl_rs_selftest_panic(void);
int ftl_rs_fork_test(unsigned int children);
#endif

#endif // FTL_RS_H
