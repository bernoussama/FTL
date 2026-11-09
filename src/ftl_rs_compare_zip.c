/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare zip: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "zip/miniz/miniz.h"
#include "ftl_rs.h"

// The C reference (miniz) and the Rust module read the same archive bytes. Each
// reader produces a trace: the open result, the member count, and for each member
// the stat and the extraction, with the last error after every operation. The
// traces are compared entry by entry. Writer output bytes are never compared.
//   - valid archives, written by miniz and by Rust, read by both readers
//   - MUTATIONS mutations of a few base archives, and every truncation of the
//     small ones. The C reader runs in a forked child, so a crash or a hang of C
//     is a C crash and not a difference

// Differences after this many are counted, not printed
#define MAX_SHOWN 50
#define MAX_CRASHES_SHOWN 10
// Random mutations of each base archive (every truncation of the small ones is
// run on top of these)
#define MUTATIONS_PER_BASE 1000
// Members bigger than this are not extracted in the mutation pass (on both sides)
#define MUTATION_EXTRACT_LIMIT (1024u * 1024u)
#define ONE_MIB (1024u * 1024u)
// Archives under this size get every truncation
#define SMALL_ARCHIVE 1024
// The C child is killed after this many seconds, which is a hang and a crash
#define CHILD_TIMEOUT_S 5
// Exit status of the C child when it could not write its trace
#define CHILD_FAILED 3
// Result of run_c_child()
#define RUN_OK 0
#define RUN_CRASH 1
#define RUN_SETUP 2
// Operations of a trace
#define OP_OPEN 0
#define OP_NUM 1
#define OP_STAT 2
#define OP_EXTRACT 3
// No limit on the size of extracted members
#define NO_LIMIT UINT64_MAX
// Output buffers are pre-filled with this, so that "left untouched" is visible
#define FILL_BYTE 0xA5
// Last-modified time of every member, in MS-DOS format
#define DOS_TIME 0x6000
#define DOS_DATE 0x5A21
// Sizes of the member name and comment buffers (names up to 600 bytes, comments
// up to 300)
#define NAME_SIZE 704
#define COMMENT_SIZE 320
// Seed of the xorshift64 generator
#define PRNG_SEED 0x9E3779B97F4A7C15ULL

static uint64_t rng_state = PRNG_SEED;
static unsigned int inputs = 0;
static unsigned int differences = 0;
static unsigned int documented = 0;
static unsigned int crashes = 0;
static unsigned int crashes_shown = 0;
static unsigned int mutations = 0;
static unsigned int skipped = 0;
static unsigned int shown = 0;

// A growing byte buffer
struct bytes {
	uint8_t *data;
	size_t len;
	size_t cap;
};

// A member of an archive to write
struct member {
	char name[NAME_SIZE];
	char comment[COMMENT_SIZE];
	uint8_t *data;
	size_t len;
};

// One result of a trace. Fields are ordered so that the struct has no padding,
// as it is sent through the pipe as it is. An EXTRACT entry carries the stat of
// its member too (the documented-difference check needs it)
struct entry {
	uint64_t comp_size;
	uint64_t uncomp_size;
	uint64_t local_header_ofs;
	uint64_t hash;
	uint32_t index;
	uint32_t value;
	uint32_t err;
	uint32_t crc32;
	uint32_t external_attr;
	uint16_t method;
	uint16_t bit_flag;
	uint16_t dos_time;
	uint16_t dos_date;
	uint8_t kind;
	uint8_t ok;
	uint8_t is_directory;
	uint8_t pad;
	char name[512];
	char comment[512];
};

// The results of one reader on one archive, in order
struct trace {
	struct entry *items;
	size_t count;
	size_t cap;
};

// A base archive to mutate
struct base {
	const char *name;
	struct bytes data;
};

static void out_of_memory(void)
{
	printf("rust-compare zip: out of memory\n");
	exit(EXIT_FAILURE);
}

static void *xalloc(const size_t n)
{
	void *p = malloc(n > 0 ? n : 1);
	if(p == NULL)
		out_of_memory();
	return p;
}

// Appends n bytes from data to b
static void append(struct bytes *b, const void *data, const size_t n)
{
	if(n > b->cap - b->len)
	{
		size_t cap = 2 * b->cap;
		if(cap < b->len + n)
			cap = b->len + n;
		uint8_t *grown = realloc(b->data, cap);
		if(grown == NULL)
			out_of_memory();
		b->data = grown;
		b->cap = cap;
	}
	if(n > 0)
		memcpy(b->data + b->len, data, n);
	b->len += n;
}

// Makes b a copy of len bytes from src (b must be empty). Always has a data pointer
static void set_copy(struct bytes *b, const uint8_t *src, const size_t len)
{
	b->data = xalloc(len);
	if(len > 0)
		memcpy(b->data, src, len);
	b->len = len;
	b->cap = len;
}

static void free_bytes(struct bytes *b)
{
	free(b->data);
	*b = (struct bytes){ NULL, 0, 0 };
}

// Appends everything that fd has to b, up to its end. Returns false on a read error
static bool read_all(const int fd, struct bytes *b)
{
	uint8_t chunk[16384];
	for(;;)
	{
		const ssize_t n = read(fd, chunk, sizeof(chunk));
		if(n == 0)
			return true;
		if(n < 0)
		{
			if(errno == EINTR)
				continue;
			return false;
		}
		append(b, chunk, (size_t)n);
	}
}

// Writes all of data to fd. Returns false on a write error
static bool write_all(const int fd, const void *data, size_t n)
{
	const uint8_t *p = data;
	while(n > 0)
	{
		const ssize_t written = write(fd, p, n);
		if(written < 0)
		{
			if(errno == EINTR)
				continue;
			return false;
		}
		p += written;
		n -= (size_t)written;
	}
	return true;
}

// xorshift64, with a fixed seed. Every run makes the same mutations
static uint64_t next_random(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static uint32_t random_u32(void)
{
	return (uint32_t)(next_random() >> 32);
}

// A random number in 0 to n-1 (0 for n 0)
static size_t random_below(const size_t n)
{
	return n == 0 ? 0 : (size_t)(next_random() % n);
}

// The FNV-1a hash of n copies of byte, as fnv1a() gives for such a buffer
static uint64_t fnv1a_fill(const uint8_t byte, const uint64_t n)
{
	uint64_t h = 14695981039346656037ULL;
	for(uint64_t i = 0; i < n; i++)
	{
		h ^= byte;
		h *= 1099511628211ULL;
	}
	return h;
}

// FNV-1a of n bytes, the hash of an extracted member
static uint64_t fnv1a(const uint8_t *p, const size_t n)
{
	uint64_t h = 14695981039346656037ULL;
	for(size_t i = 0; i < n; i++)
	{
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

// Counts a difference that has no field, and prints it while the cap allows
static void difference_msg(const char *label, const char *what)
{
	differences++;
	if(shown < MAX_SHOWN)
	{
		shown++;
		printf("difference: %s: %s\n", label, what);
	}
}

// Counts a difference of a number field, and prints it while the cap allows
static void diff_num(const char *label, const char *op, const uint32_t idx, const char *field,
                     const unsigned long long c, const unsigned long long r)
{
	if(c == r)
		return;
	differences++;
	if(shown < MAX_SHOWN)
	{
		shown++;
		printf("difference: %s, %s %u, %s: C=%llu Rust=%llu\n", label, op, idx, field, c, r);
	}
}

// Counts a difference of a text field, and prints it while the cap allows
static void diff_text(const char *label, const char *op, const uint32_t idx, const char *field,
                      const char *c, const char *r)
{
	if(strcmp(c, r) == 0)
		return;
	differences++;
	if(shown < MAX_SHOWN)
	{
		shown++;
		printf("difference: %s, %s %u, %s: C=%.60s Rust=%.60s\n", label, op, idx, field, c, r);
	}
}

// Zeroes an entry and sets its kind and member index
static void zero_entry(struct entry *e, const int kind, const uint32_t idx)
{
	memset(e, 0, sizeof(*e));
	e->kind = (uint8_t)kind;
	e->index = idx;
}

// Copies a NUL-terminated text, cut to cap-1 bytes, into dst (zeroed)
static void copy_text(char *dst, const char *src, const size_t cap)
{
	size_t n = 0;
	while(n + 1 < cap && src[n] != '\0')
		n++;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

static void push(struct trace *t, const struct entry *e)
{
	if(t->count == t->cap)
	{
		const size_t cap = t->cap > 0 ? 2 * t->cap : 64;
		struct entry *grown = realloc(t->items, cap * sizeof(*grown));
		if(grown == NULL)
			out_of_memory();
		t->items = grown;
		t->cap = cap;
	}
	t->items[t->count++] = *e;
}

static void free_trace(struct trace *t)
{
	free(t->items);
	*t = (struct trace){ NULL, 0, 0 };
}

// The stat of member idx with miniz, and its extraction into a buffer of the exact
// size (pre-filled), with the last error after each. The MS-DOS time and date are
// read from the central directory entry, as miniz's stat does not keep them
static void trace_c_member(mz_zip_archive *zip, const uint32_t idx, const uint64_t limit, struct trace *t)
{
	mz_zip_archive_file_stat st;
	struct entry e;
	memset(&st, 0, sizeof(st));
	zero_entry(&e, OP_STAT, idx);
	e.ok = mz_zip_reader_file_stat(zip, idx, &st) != MZ_FALSE ? 1 : 0;
	const mz_zip_error stat_err = mz_zip_get_last_error(zip);
	e.err = (uint32_t)stat_err;
	if(e.ok)
	{
		e.method = st.m_method;
		e.bit_flag = st.m_bit_flag;
		e.crc32 = st.m_crc32;
		e.external_attr = st.m_external_attr;
		e.is_directory = st.m_is_directory != MZ_FALSE ? 1 : 0;
		e.comp_size = st.m_comp_size;
		e.uncomp_size = st.m_uncomp_size;
		e.local_header_ofs = st.m_local_header_ofs;
		copy_text(e.name, st.m_filename, sizeof(e.name));
		copy_text(e.comment, st.m_comment, sizeof(e.comment));
		// The central directory entry: time at 12, date at 14 (little endian)
		uint8_t raw[4] = { 0, 0, 0, 0 };
		mz_zip_read_archive_data(zip, zip->m_central_directory_file_ofs + st.m_central_dir_ofs + 12, raw, sizeof(raw));
		e.dos_time = (uint16_t)(raw[0] | (raw[1] << 8));
		e.dos_date = (uint16_t)(raw[2] | (raw[3] << 8));
	}
	push(t, &e);
	if(!e.ok)
		return;
	if(e.uncomp_size > limit)
		return;

	const size_t size = (size_t)e.uncomp_size;
	uint8_t *buf = xalloc(size);
	memset(buf, FILL_BYTE, size > 0 ? size : 1);
	struct entry x;
	zero_entry(&x, OP_EXTRACT, idx);
	x.ok = mz_zip_reader_extract_to_mem(zip, idx, buf, size, 0) != MZ_FALSE ? 1 : 0;
	const mz_zip_error extract_err = mz_zip_get_last_error(zip);
	x.err = (uint32_t)extract_err;
	x.hash = fnv1a(buf, size);
	x.comp_size = e.comp_size;
	x.uncomp_size = e.uncomp_size;
	x.is_directory = e.is_directory;
	push(t, &x);
	free(buf);
}

// The trace of miniz on an archive: open, member count, then each member
static void trace_c(const uint8_t *data, const size_t len, const uint64_t limit, struct trace *t)
{
	mz_zip_archive zip;
	mz_zip_zero_struct(&zip);
	struct entry e;
	zero_entry(&e, OP_OPEN, 0);
	const mz_bool opened = mz_zip_reader_init_mem(&zip, data, len, 0);
	const mz_zip_error open_err = mz_zip_get_last_error(&zip);
	e.value = (uint32_t)open_err;
	e.ok = opened != MZ_FALSE ? 1 : 0;
	e.err = e.value;
	push(t, &e);
	if(!opened)
		return;

	struct entry n;
	zero_entry(&n, OP_NUM, 0);
	n.value = mz_zip_reader_get_num_files(&zip);
	n.ok = 1;
	push(t, &n);
	for(uint32_t idx = 0; idx < n.value; idx++)
		trace_c_member(&zip, idx, limit, t);
	mz_zip_reader_end(&zip);
}

// The stat of member idx with Rust, and its extraction, as trace_c_member() does it
static void trace_r_member(ftl_rs_zip_reader *reader, const uint32_t idx, const uint64_t limit, struct trace *t)
{
	ftl_rs_zip_stat st;
	struct entry e;
	memset(&st, 0, sizeof(st));
	zero_entry(&e, OP_STAT, idx);
	e.ok = ftl_rs_zip_file_stat(reader, idx, &st) ? 1 : 0;
	e.err = ftl_rs_zip_last_error(reader);
	if(e.ok)
	{
		e.method = st.method;
		e.bit_flag = st.bit_flag;
		e.dos_time = st.dos_time;
		e.dos_date = st.dos_date;
		e.crc32 = st.crc32;
		e.external_attr = st.external_attr;
		e.is_directory = st.is_directory ? 1 : 0;
		e.comp_size = st.comp_size;
		e.uncomp_size = st.uncomp_size;
		e.local_header_ofs = st.local_header_ofs;
		copy_text(e.name, st.name, sizeof(e.name));
		copy_text(e.comment, st.comment, sizeof(e.comment));
	}
	push(t, &e);
	if(!e.ok)
		return;
	if(e.uncomp_size > limit)
	{
		skipped++;
		return;
	}

	const size_t size = (size_t)e.uncomp_size;
	uint8_t *buf = xalloc(size);
	memset(buf, FILL_BYTE, size > 0 ? size : 1);
	struct entry x;
	zero_entry(&x, OP_EXTRACT, idx);
	x.ok = ftl_rs_zip_extract(reader, idx, buf, size) ? 1 : 0;
	x.err = ftl_rs_zip_last_error(reader);
	x.hash = fnv1a(buf, size);
	x.comp_size = e.comp_size;
	x.uncomp_size = e.uncomp_size;
	x.is_directory = e.is_directory;
	push(t, &x);
	free(buf);
}

// The trace of the Rust module on an archive, as trace_c() does it
static void trace_r(const uint8_t *data, const size_t len, const uint64_t limit, struct trace *t)
{
	ftl_rs_zip_reader *reader = NULL;
	struct entry e;
	zero_entry(&e, OP_OPEN, 0);
	e.value = ftl_rs_zip_open(data, len, &reader);
	e.ok = e.value == 0 ? 1 : 0;
	// Without a reader, the last error is the one that opening gave
	e.err = reader != NULL ? ftl_rs_zip_last_error(reader) : e.value;
	push(t, &e);
	if(reader == NULL)
		return;

	struct entry n;
	zero_entry(&n, OP_NUM, 0);
	n.value = ftl_rs_zip_num_files(reader);
	n.ok = 1;
	push(t, &n);
	for(uint32_t idx = 0; idx < n.value; idx++)
		trace_r_member(reader, idx, limit, t);
	ftl_rs_zip_reader_free(reader);
}

// Whether a C extraction that succeeded without writing, and a Rust extraction that
// failed with UNEXPECTED_DECOMPRESSED_SIZE, is the documented difference. miniz returns
// success and leaves the buffer untouched for a directory (DOS attribute or trailing
// '/') and for a member with comp_size 0. With uncomp_size > 0 the data is corrupt, and
// the caller would get bytes that nothing wrote. The teleporter does not check
// is_directory, so under miniz it would import them. Rust keeps the error (reader.rs)
static bool documented_case(const struct entry *c, const struct entry *r)
{
	return c->kind == OP_EXTRACT && c->ok && c->err == 0 && !r->ok
	       && r->err == (uint32_t)MZ_ZIP_UNEXPECTED_DECOMPRESSED_SIZE
	       && (c->is_directory || c->comp_size == 0) && c->uncomp_size > 0
	       // miniz wrote nothing, so the buffer still holds FILL_BYTE
	       && c->hash == fnv1a_fill(FILL_BYTE, c->uncomp_size);
}

// Compares the fields of one pair of entries that have the same kind
static void compare_entry(const char *label, const struct entry *c, const struct entry *r)
{
	const char *op = c->kind == OP_OPEN ? "open" : c->kind == OP_NUM ? "file count" : c->kind == OP_STAT ? "stat" : "extract";
	const uint32_t idx = c->index;
	if(c->kind == OP_OPEN)
	{
		diff_num(label, op, idx, "result", c->ok, r->ok);
		diff_num(label, op, idx, "open error", c->value, r->value);
		diff_num(label, op, idx, "last error", c->err, r->err);
	}
	else if(c->kind == OP_NUM)
		diff_num(label, op, idx, "files", c->value, r->value);
	else if(c->kind == OP_STAT)
	{
		diff_num(label, op, idx, "success", c->ok, r->ok);
		diff_num(label, op, idx, "last error", c->err, r->err);
		diff_num(label, op, idx, "method", c->method, r->method);
		diff_num(label, op, idx, "bit_flag", c->bit_flag, r->bit_flag);
		diff_num(label, op, idx, "dos_time", c->dos_time, r->dos_time);
		diff_num(label, op, idx, "dos_date", c->dos_date, r->dos_date);
		diff_num(label, op, idx, "crc32", c->crc32, r->crc32);
		diff_num(label, op, idx, "external_attr", c->external_attr, r->external_attr);
		diff_num(label, op, idx, "is_directory", c->is_directory, r->is_directory);
		diff_num(label, op, idx, "comp_size", c->comp_size, r->comp_size);
		diff_num(label, op, idx, "uncomp_size", c->uncomp_size, r->uncomp_size);
		diff_num(label, op, idx, "local_header_ofs", c->local_header_ofs, r->local_header_ofs);
		diff_text(label, op, idx, "name", c->name, r->name);
		diff_text(label, op, idx, "comment", c->comment, r->comment);
	}
	else
	{
		diff_num(label, op, idx, "success", c->ok, r->ok);
		diff_num(label, op, idx, "last error", c->err, r->err);
		// After a failed extraction the buffer holds the bytes decoded before the failure.
		// Those differ between miniz and miniz_oxide (both fail, and both leave the last
		// error unset), and a caller must not use them, so only a success is compared
		if(c->ok && r->ok)
			diff_num(label, op, idx, "content hash", c->hash, r->hash);
	}
}

// Compares two traces entry by entry. A count mismatch is a difference, and the
// entries up to the shorter trace are still compared. A kind mismatch ends it
static void compare_traces(const char *label, const struct trace *c, const struct trace *r)
{
	if(c->count != r->count)
	{
		char what[96];
		snprintf(what, sizeof(what), "%zu operations for C, %zu for Rust", c->count, r->count);
		difference_msg(label, what);
	}
	const size_t n = c->count < r->count ? c->count : r->count;
	for(size_t i = 0; i < n; i++)
	{
		const struct entry *ec = &c->items[i];
		const struct entry *er = &r->items[i];
		if(ec->kind != er->kind)
		{
			difference_msg(label, "the operations differ in kind");
			return;
		}
		if(documented_case(ec, er))
		{
			documented++;
			continue;
		}
		compare_entry(label, ec, er);
	}
}

// Checks a trace of a valid archive against what was written: it opens, has the
// members that were written, and each member extracts to its original data
static void check_content(const char *label, const struct trace *t, const struct member *m, const size_t n)
{
	for(size_t i = 0; i < t->count; i++)
	{
		const struct entry *e = &t->items[i];
		if(e->kind == OP_OPEN && !e->ok)
			difference_msg(label, "a valid archive does not open");
		else if(e->kind == OP_NUM && e->value != n)
			difference_msg(label, "the member count is not the number written");
		else if(e->kind == OP_STAT && !e->ok)
			difference_msg(label, "a valid archive member does not stat");
		else if(e->kind == OP_EXTRACT && (!e->ok || e->index >= n || e->hash != fnv1a(m[e->index].data, m[e->index].len)))
			difference_msg(label, "an extracted member is not its original data");
	}
}

// Fills a member name: plain, 300 bytes, 600 bytes, a directory, or UTF-8
static void fill_name(char *dst, const size_t kind, const size_t idx)
{
	if(kind == 0)
		snprintf(dst, NAME_SIZE, "file-%02zu.txt", idx);
	else if(kind == 1)
		snprintf(dst, NAME_SIZE, "%0*zu", 300, idx);
	else if(kind == 2)
		snprintf(dst, NAME_SIZE, "%0*zu", 600, idx);
	else if(kind == 3)
		snprintf(dst, NAME_SIZE, "dir-%02zu/", idx);
	else
		snprintf(dst, NAME_SIZE, "caf\xc3\xa9-%02zu-\xe6\x97\xa5\xe6\x9c\xac.txt", idx);
}

// Fills a member comment: empty, short, or 300 bytes
static void fill_comment(char *dst, const size_t kind, const size_t idx)
{
	if(kind == 0)
		dst[0] = '\0';
	else if(kind == 1)
		snprintf(dst, COMMENT_SIZE, "short comment %zu", idx);
	else
		snprintf(dst, COMMENT_SIZE, "%0*zu", 300, idx);
}

// Fills len bytes: a repeated pattern (compressible), or pseudo-random bytes
static void fill_data(uint8_t *buf, const size_t len, const bool compressible, const size_t seed)
{
	for(size_t i = 0; i < len; i++)
		buf[i] = compressible ? (uint8_t)"0123456789abcdef"[(i + seed) % 16] : (uint8_t)random_u32();
}

// Makes count members. Member i has the name kind (i * 3) % 5, the comment kind i % 3,
// and the size sizes[i % n_sizes] (0 for a directory). data_kind is 0 for compressible
// data, 1 for pseudo-random data, and -1 for both, alternately
static struct member *make_members(const size_t count, const size_t *sizes, const size_t n_sizes, const int data_kind)
{
	struct member *m = xalloc(count * sizeof(*m));
	for(size_t i = 0; i < count; i++)
	{
		const size_t name_kind = (i * 3) % 5;
		fill_name(m[i].name, name_kind, i);
		fill_comment(m[i].comment, i % 3, i);
		const bool compressible = data_kind < 0 ? i % 2 == 0 : data_kind == 0;
		m[i].len = name_kind == 3 ? 0 : sizes[i % n_sizes];
		m[i].data = xalloc(m[i].len);
		fill_data(m[i].data, m[i].len, compressible, i);
	}
	return m;
}

static void free_members(struct member *m, const size_t count)
{
	for(size_t i = 0; i < count; i++)
		free(m[i].data);
	free(m);
}

// Writes the members with miniz (default level). The MS-DOS time is the time miniz
// records, as the writer output is not compared
static bool c_write(const struct member *m, const size_t n, struct bytes *out, const char *desc)
{
	mz_zip_archive zip;
	mz_zip_zero_struct(&zip);
	if(!mz_zip_writer_init_heap(&zip, 0, 0))
	{
		difference_msg(desc, "C writer: mz_zip_writer_init_heap failed");
		return false;
	}
	for(size_t i = 0; i < n; i++)
	{
		if(!mz_zip_writer_add_mem_ex(&zip, m[i].name, m[i].data, m[i].len, m[i].comment,
		                             (mz_uint16)strlen(m[i].comment), (mz_uint)MZ_DEFAULT_COMPRESSION, 0, 0))
		{
			char what[160];
			snprintf(what, sizeof(what), "C writer: member %zu failed: %s", i,
			         mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
			difference_msg(desc, what);
			mz_zip_writer_end(&zip);
			return false;
		}
	}
	void *ptr = NULL;
	size_t size = 0;
	if(!mz_zip_writer_finalize_heap_archive(&zip, &ptr, &size))
	{
		char what[160];
		snprintf(what, sizeof(what), "C writer: finalize failed: %s",
		         mz_zip_get_error_string(mz_zip_get_last_error(&zip)));
		difference_msg(desc, what);
		mz_zip_writer_end(&zip);
		return false;
	}
	append(out, ptr, size);
	free(ptr);
	mz_zip_writer_end(&zip);
	return true;
}

// Writes the members with the Rust module, with the same MS-DOS time and date
static bool rust_write(const struct member *m, const size_t n, struct bytes *out, const char *desc)
{
	ftl_rs_zip_writer *writer = ftl_rs_zip_writer_new();
	if(writer == NULL)
	{
		difference_msg(desc, "Rust writer: ftl_rs_zip_writer_new returned NULL");
		return false;
	}
	for(size_t i = 0; i < n; i++)
	{
		const uint32_t err = ftl_rs_zip_writer_add(writer, m[i].name, m[i].data, m[i].len, m[i].comment, DOS_TIME, DOS_DATE);
		if(err != 0)
		{
			char what[128];
			snprintf(what, sizeof(what), "Rust writer: member %zu failed with %u", i, err);
			difference_msg(desc, what);
			ftl_rs_zip_writer_free(writer);
			return false;
		}
	}
	ftl_rs_buf buf = { NULL, 0, 0 };
	const uint32_t err = ftl_rs_zip_writer_finish(writer, &buf);
	ftl_rs_zip_writer_free(writer);
	if(err != 0)
	{
		char what[128];
		snprintf(what, sizeof(what), "Rust writer: finish failed with %u", err);
		difference_msg(desc, what);
		return false;
	}
	append(out, buf.ptr, buf.len);
	ftl_rs_buf_free(&buf);
	return true;
}

// Compares both readers on one valid archive, and checks the content against m
static void run_valid(const char *desc, const struct bytes *archive, const struct member *m, const size_t n)
{
	char label[192];
	struct trace c = { NULL, 0, 0 };
	struct trace r = { NULL, 0, 0 };
	inputs++;
	snprintf(label, sizeof(label), "input %u (%s)", inputs, desc);
	trace_c(archive->data, archive->len, NO_LIMIT, &c);
	trace_r(archive->data, archive->len, NO_LIMIT, &r);
	compare_traces(label, &c, &r);
	check_content(label, &c, m, n);
	check_content(label, &r, m, n);
	free_trace(&c);
	free_trace(&r);
}

// Writes a list of members with both writers, and runs both readers on each archive
static void run_list(const char *name, struct member *m, const size_t n)
{
	char desc[160];
	struct bytes archive = { NULL, 0, 0 };
	snprintf(desc, sizeof(desc), "%s, C writer", name);
	if(c_write(m, n, &archive, desc))
		run_valid(desc, &archive, m, n);
	free_bytes(&archive);
	snprintf(desc, sizeof(desc), "%s, Rust writer", name);
	if(rust_write(m, n, &archive, desc))
		run_valid(desc, &archive, m, n);
	free_bytes(&archive);
	free_members(m, n);
}

// The valid archives: counts 0, 1, 2, 7 and 40, every data size (compressible and
// pseudo-random), and a 1 MiB + 1 pseudo-random member
static void run_valid_archives(void)
{
	static const size_t sizes[] = { 0, 1, 3, 4, 100, 4096, 65536, ONE_MIB + 1 };
	static const size_t mixed[] = { 0, 1, 3, 4, 100, 4096, 65536 };
	static const size_t pair[] = { 100, 3 };
	static const size_t tiny[] = { 4, 1 };
	static const size_t big[] = { ONE_MIB + 1 };
	char name[96];

	run_list("0 members", make_members(0, mixed, 7, -1), 0);
	run_list("2 members, 100 and 3 bytes", make_members(2, pair, 2, -1), 2);
	run_list("7 members, mixed", make_members(7, mixed, 7, -1), 7);
	run_list("40 members, mixed", make_members(40, sizes, 8, -1), 40);
	run_list("2 members, tiny", make_members(2, tiny, 2, -1), 2);
	run_list("3 members, 1 MiB + 1 bytes, pseudo-random", make_members(3, big, 1, 1), 3);
	for(size_t s = 0; s < 8; s++)
		for(int kind = 0; kind < 2; kind++)
		{
			snprintf(name, sizeof(name), "1 member of %zu bytes, %s", sizes[s], kind ? "pseudo-random" : "compressible");
			run_list(name, make_members(1, &sizes[s], 1, kind), 1);
		}
}

// Runs the C reader on buf in a forked child, which sends its trace through a pipe.
// A signal, a non-zero exit, a hang (alarm) or a short trace is RUN_CRASH
static int run_c_child(const struct bytes *buf, struct trace *t)
{
	int fds[2];
	if(pipe(fds) != 0)
		return RUN_SETUP;
	// Flushed before the fork, or the child would print it a second time
	fflush(stdout);
	const pid_t pid = fork();
	if(pid < 0)
	{
		close(fds[0]);
		close(fds[1]);
		return RUN_SETUP;
	}
	if(pid == 0)
	{
		// The child reads its copy of the archive, and sends the trace as it is
		close(fds[0]);
		signal(SIGALRM, SIG_DFL);
		alarm(CHILD_TIMEOUT_S);
		struct trace c = { NULL, 0, 0 };
		trace_c(buf->data, buf->len, MUTATION_EXTRACT_LIMIT, &c);
		const bool written = write_all(fds[1], c.items, c.count * sizeof(*c.items));
		_exit(written ? EXIT_SUCCESS : CHILD_FAILED);
	}
	close(fds[1]);
	struct bytes raw = { NULL, 0, 0 };
	const bool read_ok = read_all(fds[0], &raw);
	close(fds[0]);
	int status = 0;
	pid_t waited;
	do
	{
		waited = waitpid(pid, &status, 0);
	} while(waited < 0 && errno == EINTR);
	const bool exited_ok = waited == pid && WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
	if(!read_ok || !exited_ok || raw.len % sizeof(struct entry) != 0)
	{
		free_bytes(&raw);
		return RUN_CRASH;
	}
	t->count = raw.len / sizeof(struct entry);
	t->cap = t->count;
	t->items = xalloc(raw.len);
	if(raw.len > 0)
		memcpy(t->items, raw.data, raw.len);
	free_bytes(&raw);
	return RUN_OK;
}

// Runs one mutated archive: C in a child, Rust in process on its own copy. A C
// crash is counted and not compared. Members over MUTATION_EXTRACT_LIMIT are skipped.
// The Rust reader runs in this process, so an abort there ends the run with no
// result line (the bats test fails then) and is not attributed to a mutant
static void run_mutant(const char *desc, const struct bytes *buf)
{
	char label[192];
	struct trace c = { NULL, 0, 0 };
	struct trace r = { NULL, 0, 0 };
	struct bytes copy = { NULL, 0, 0 };
	inputs++;
	mutations++;
	snprintf(label, sizeof(label), "input %u (%s)", inputs, desc);
	const int status = run_c_child(buf, &c);
	set_copy(&copy, buf->data, buf->len);
	trace_r(copy.data, copy.len, MUTATION_EXTRACT_LIMIT, &r);
	free_bytes(&copy);
	if(status == RUN_SETUP)
		difference_msg(label, "the C child could not be started");
	else if(status == RUN_CRASH)
	{
		crashes++;
		if(crashes_shown < MAX_CRASHES_SHOWN)
		{
			crashes_shown++;
			printf("C CRASH on %s\n", label);
		}
	}
	else
		compare_traces(label, &c, &r);
	free_trace(&c);
	free_trace(&r);
}

// Makes one mutation of base into out (from the base, never chained). Returns its kind
static const char *mutate(const struct bytes *base, struct bytes *out)
{
	static const char *const names[] = { "flip bit", "set byte", "u32 field", "u16 field", "truncate", "random buffer" };
	size_t kind = random_below(6);
	set_copy(out, base->data, base->len);
	if(kind == 0 && out->len > 0)
	{
		const size_t pos = random_below(out->len);
		out->data[pos] ^= (uint8_t)(1u << random_below(8));
	}
	else if(kind == 1 && out->len > 0)
		out->data[random_below(out->len)] = (uint8_t)random_u32();
	else if(kind == 2 && out->len >= 4)
	{
		static const uint32_t values[] = { 0, 0xFFFFFFFFu, 0x80000000u };
		const size_t pick = random_below(4);
		const uint32_t v = pick < 3 ? values[pick] : random_u32();
		const size_t at = random_below(out->len - 3);
		for(unsigned int j = 0; j < 4; j++)
			out->data[at + j] = (uint8_t)(v >> (8 * j));
	}
	else if(kind == 3 && out->len >= 2)
	{
		static const uint16_t values[] = { 0, 0xFFFFu };
		const size_t pick = random_below(3);
		const uint16_t v = (uint16_t)(pick < 2 ? values[pick] : (uint16_t)random_u32());
		const size_t at = random_below(out->len - 1);
		out->data[at] = (uint8_t)v;
		out->data[at + 1] = (uint8_t)(v >> 8);
	}
	else if(kind == 4 && out->len > 0)
		out->len = random_below(out->len);
	else
	{
		kind = 5;
		free_bytes(out);
		const size_t len = random_below(513);
		out->data = xalloc(len);
		for(size_t i = 0; i < len; i++)
			out->data[i] = (uint8_t)random_u32();
		out->len = len;
		out->cap = len;
	}
	return names[kind];
}

// Every truncation of the small bases, then MUTATIONS_PER_BASE mutations of each
static void run_mutations(void)
{
	static const size_t mixed[] = { 0, 1, 3, 4, 100, 4096, 65536 };
	static const size_t tiny[] = { 4, 1 };
	struct member *m7 = make_members(7, mixed, 7, -1);
	struct member *m0 = make_members(0, mixed, 7, -1);
	struct member *mt = make_members(2, tiny, 2, -1);
	struct base bases[4] = {
		{ "C-written 7 members", { NULL, 0, 0 } },
		{ "Rust-written 7 members", { NULL, 0, 0 } },
		{ "C-written 0 members", { NULL, 0, 0 } },
		{ "C-written tiny archive", { NULL, 0, 0 } },
	};
	c_write(m7, 7, &bases[0].data, "base C-written 7 members");
	rust_write(m7, 7, &bases[1].data, "base Rust-written 7 members");
	c_write(m0, 0, &bases[2].data, "base C-written 0 members");
	c_write(mt, 2, &bases[3].data, "base C-written tiny archive");

	for(size_t b = 0; b < 4; b++)
	{
		char desc[160];
		const struct base *base = &bases[b];
		if(base->data.len < SMALL_ARCHIVE)
			for(size_t len = 0; len < base->data.len; len++)
			{
				struct bytes cut = { NULL, 0, 0 };
				set_copy(&cut, base->data.data, len);
				snprintf(desc, sizeof(desc), "truncation to %zu bytes of %s", len, base->name);
				run_mutant(desc, &cut);
				free_bytes(&cut);
			}
		for(unsigned int k = 0; k < MUTATIONS_PER_BASE; k++)
		{
			struct bytes mut = { NULL, 0, 0 };
			const char *what = mutate(&base->data, &mut);
			snprintf(desc, sizeof(desc), "mutation %u of %s (%s)", k, base->name, what);
			run_mutant(desc, &mut);
			free_bytes(&mut);
		}
	}
	for(size_t b = 0; b < 4; b++)
		free_bytes(&bases[b].data);
	free_members(m7, 7);
	free_members(m0, 0);
	free_members(mt, 2);
}

int ftl_rs_compare_zip(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	run_valid_archives();
	run_mutations();
	printf("rust-compare zip: documented differences: %u\n", documented);
	printf("rust-compare zip: C crashes: %u\n", crashes);
	printf("rust-compare zip: %u mutations, %u skipped large extractions\n", mutations, skipped);
	printf("rust-compare zip: %u inputs, %u differences\n", inputs, differences);
	// A C crash is a C bug, so it fails the run as a difference does
	return differences == 0 && crashes == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
