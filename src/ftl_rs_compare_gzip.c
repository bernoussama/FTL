/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare gzip: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ftl_rs.h"
#include "log.h"
#include "zip/gzip.h"

// Differences, C crashes and inputs after this many are counted, not printed
#define MAX_SHOWN 50
// Mutated copies of the seeds, on top of every prefix of the short seeds
#define MUTATIONS 3000
// Seeds up to this length get every prefix tried
#define MAX_PREFIX_SEED 256
// Longest log text of a rejected stream that is shown
#define MAX_LOG_SHOWN 512
// Exit status of the forked child for a rejected stream (0 is accepted). Any
// other exit status, or a signal, is a crash
#define CHILD_REJECTED 2
#define CHILD_FAILED 3
// Header flags of the generated streams (RFC 1952 section 2.3.1)
#define GZIP_FTEXT 0x01
#define GZIP_FHCRC 0x02
#define GZIP_FEXTRA 0x04
#define GZIP_FNAME 0x08
#define GZIP_FCOMMENT 0x10
// The mtime of the generated streams
#define MTIME 1700000000u

static unsigned int inputs = 0;
static unsigned int differences = 0;
static unsigned int documented = 0;
static unsigned int crashes = 0;
static uint64_t rng_state = 1;

// A growing byte buffer
struct bytes {
	unsigned char *data;
	size_t len;
	size_t cap;
};

// A stream to mutate, with the name it is shown by
struct seed {
	const char *name;
	struct bytes stream;
};

static struct seed *seeds = NULL;
static size_t seed_count = 0;

// What the C reference did with one stream, as the parent sees it
struct c_run {
	bool crashed; // the child did not exit as expected
	bool accepted;
	struct bytes output; // the output of an accepted stream
	struct bytes log; // the log text of a rejected stream
};

static void out_of_memory(void)
{
	printf("rust-compare gzip: out of memory\n");
	exit(EXIT_FAILURE);
}

// Appends n bytes from data to b. The inputs are small, so running out of memory ends the run
static void append(struct bytes *b, const void *data, const size_t n)
{
	if(n > b->cap - b->len)
	{
		size_t cap = 2 * b->cap;
		if(cap < b->len + n)
			cap = b->len + n;
		unsigned char *grown = realloc(b->data, cap);
		if(grown == NULL)
			out_of_memory();
		b->data = grown;
		b->cap = cap;
	}
	if(n > 0)
		memcpy(b->data + b->len, data, n);
	b->len += n;
}

static void free_bytes(struct bytes *b)
{
	free(b->data);
	*b = (struct bytes){ NULL, 0, 0 };
}

static bool same_bytes(const unsigned char *a, const size_t a_len, const unsigned char *b, const size_t b_len)
{
	return a_len == b_len && (a_len == 0 || memcmp(a, b, a_len) == 0);
}

// Appends everything that fd has to b, up to its end. Returns false on a read error
static bool read_all(const int fd, struct bytes *b)
{
	unsigned char chunk[16384];
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
static bool write_all(const int fd, const unsigned char *data, size_t n)
{
	while(n > 0)
	{
		const ssize_t written = write(fd, data, n);
		if(written < 0)
		{
			if(errno == EINTR)
				continue;
			return false;
		}
		data += written;
		n -= (size_t)written;
	}
	return true;
}

static bool read_file(const char *path, struct bytes *b)
{
	const int fd = open(path, O_RDONLY);
	if(fd < 0)
		return false;
	const bool ok = read_all(fd, b);
	close(fd);
	return ok;
}

// Counts a difference and prints it while the cap allows
static void difference(const char *input, const char *c_result, const char *rust_result)
{
	differences++;
	if(differences <= MAX_SHOWN)
		printf("difference: %s\n  C:    %s\n  Rust: %s\n", input, c_result, rust_result);
}

// Text of a result: the length and SHA-256 of an output, or the log text of a rejected stream
static void describe(char *text, const size_t size, const bool accepted, const unsigned char *data, size_t len)
{
	if(!accepted)
	{
		if(len > MAX_LOG_SHOWN)
			len = MAX_LOG_SHOWN;
		snprintf(text, size, "rejected: %.*s", (int)len, (const char *)data);
		return;
	}
	uint8_t digest[32];
	ftl_rs_sha256_buf(data, len, digest);
	static const char digits[] = "0123456789abcdef";
	char hex[2 * sizeof(digest) + 1];
	for(size_t i = 0; i < sizeof(digest); i++)
	{
		hex[2 * i] = digits[digest[i] >> 4];
		hex[2 * i + 1] = digits[digest[i] & 0x0f];
	}
	hex[sizeof(hex) - 1] = '\0';
	snprintf(text, size, "accepted, %zu bytes, sha256 %s", len, hex);
}

// Runs inflate_buffer_c() on stream in a forked child, so that a crash in C is a
// crash and does not end the comparison. The child's log goes to a pipe (log_ctrl
// prints it to stdout), its output to another, and its exit status tells whether
// it accepted the stream. Returns false if no child could be started.
static bool run_c_inflate(unsigned char *stream, const size_t len, struct c_run *run)
{
	memset(run, 0, sizeof(*run));
	int log_pipe[2];
	int result_pipe[2];
	if(pipe(log_pipe) != 0)
		return false;
	if(pipe(result_pipe) != 0)
	{
		close(log_pipe[0]);
		close(log_pipe[1]);
		return false;
	}
	// Flushed before the fork, or the child would print it a second time
	fflush(stdout);
	const pid_t pid = fork();
	if(pid < 0)
	{
		close(log_pipe[0]);
		close(log_pipe[1]);
		close(result_pipe[0]);
		close(result_pipe[1]);
		return false;
	}
	if(pid == 0)
	{
		// The child works on its own copy of stream
		close(log_pipe[0]);
		close(result_pipe[0]);
		dup2(log_pipe[1], STDOUT_FILENO);
		close(log_pipe[1]);
		log_ctrl(false, true);
		unsigned char *output = NULL;
		mz_ulong output_len = 0;
		if(!inflate_buffer_c(stream, len, &output, &output_len))
		{
			fflush(stdout);
			_exit(CHILD_REJECTED);
		}
		const bool written = write_all(result_pipe[1], output, output_len);
		fflush(stdout);
		_exit(written ? EXIT_SUCCESS : CHILD_FAILED);
	}
	close(log_pipe[1]);
	close(result_pipe[1]);
	// The result is read first, as an accepted stream can be larger than a pipe
	// buffer. The child's log is one short message, written before the result, so
	// the child never blocks on the log while the parent waits for the result
	const bool read_ok = read_all(result_pipe[0], &run->output) && read_all(log_pipe[0], &run->log);
	close(result_pipe[0]);
	close(log_pipe[0]);
	int status = 0;
	pid_t waited;
	do
	{
		waited = waitpid(pid, &status, 0);
	} while(waited < 0 && errno == EINTR);
	run->accepted = WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;
	const bool rejected = WIFEXITED(status) && WEXITSTATUS(status) == CHILD_REJECTED;
	run->crashed = !read_ok || !(run->accepted || rejected);
	return true;
}

// Whether the C log ends with the message of message_len bytes. On the CLI the log
// line is the message alone; otherwise a time and PID come before it
static bool log_ends_with(const struct bytes *text, const unsigned char *message, const size_t message_len)
{
	size_t len = text->len;
	if(len > 0 && text->data[len - 1] == '\n')
		len--;
	if(message_len == 0 || message_len > len)
		return false;
	const size_t start = len - message_len;
	if(start > 0 && text->data[start - 1] != ' ')
		return false;
	return same_bytes(text->data + start, message_len, message, message_len);
}

// Whether the C log ends with the message Rust returns
static bool same_log_text(const struct bytes *text, const ftl_rs_buf *message)
{
	return log_ends_with(text, message->ptr, message->len);
}

// The documented difference: FTL's miniz accepts an incomplete code-length table
// when it has a single code, and then reports a buffer error once its output is
// full. miniz_oxide rejects every incomplete code-length table, so Rust reports a
// data error. Both reject the stream
static bool is_documented_difference(const struct c_run *c, const bool rust_ok, const ftl_rs_buf *message)
{
	static const char c_message[] = "Failed to uncompress: buf error";
	static const char rust_message[] = "Failed to uncompress: data error";
	return !c->accepted && !rust_ok
	       && log_ends_with(&c->log, (const unsigned char *)c_message, sizeof(c_message) - 1)
	       && same_bytes(message->ptr, message->len, (const unsigned char *)rust_message, sizeof(rust_message) - 1);
}

// Reports a difference between the C result and the Rust result of one stream
static void report_difference(const char *label, const struct c_run *c, const bool rust_ok,
                              const ftl_rs_buf *output, const ftl_rs_buf *message)
{
	char c_text[MAX_LOG_SHOWN + 128];
	char rust_text[MAX_LOG_SHOWN + 128];
	describe(c_text, sizeof(c_text), c->accepted,
	         c->accepted ? c->output.data : c->log.data, c->accepted ? c->output.len : c->log.len);
	describe(rust_text, sizeof(rust_text), rust_ok,
	         rust_ok ? output->ptr : message->ptr, rust_ok ? output->len : message->len);
	difference(label, c_text, rust_text);
}

// Compares the results of the C and the Rust inflate of one stream: both have to
// accept it with the same output, or reject it with the same log text. A round
// trip (expected given) also has to give back expected
static void compare_results(const char *label, const struct c_run *c, const bool rust_ok,
                            const ftl_rs_buf *output, const ftl_rs_buf *message,
                            const unsigned char *expected, const size_t expected_len)
{
	const bool same = c->accepted == rust_ok
	                  && (rust_ok ? same_bytes(c->output.data, c->output.len, output->ptr, output->len)
	                              : same_log_text(&c->log, message));
	if(!same)
	{
		if(is_documented_difference(c, rust_ok, message))
			documented++;
		else
			report_difference(label, c, rust_ok, output, message);
		return;
	}
	if(expected != NULL && !(rust_ok && same_bytes(output->ptr, output->len, expected, expected_len)))
	{
		// C and Rust agree, but the round trip does not give back the original data
		char rust_text[MAX_LOG_SHOWN + 128];
		describe(rust_text, sizeof(rust_text), rust_ok,
		         rust_ok ? output->ptr : message->ptr, rust_ok ? output->len : message->len);
		difference(label, "the original data", rust_text);
	}
}

// Compares the C and the Rust inflate of one stream. A stream that both accept has
// to give back expected, if expected is given
static void compare_stream(const char *label, unsigned char *stream, const size_t len,
                           const unsigned char *expected, const size_t expected_len)
{
	struct c_run c;
	ftl_rs_buf output = { NULL, 0, 0 };
	ftl_rs_buf message = { NULL, 0, 0 };
	const bool started = run_c_inflate(stream, len, &c);
	const bool rust_ok = ftl_rs_gzip_inflate(stream, len, &output, &message);
	inputs++;

	if(!started)
		difference(label, "the C reference did not run", "not compared");
	else if(c.crashed)
	{
		// A C bug, so Rust only has to cope with the input
		crashes++;
		if(crashes <= MAX_SHOWN)
			printf("C crashed on: %s (a C bug, not counted as a difference)\n", label);
	}
	else
		compare_results(label, &c, rust_ok, &output, &message, expected, expected_len);

	free_bytes(&c.output);
	free_bytes(&c.log);
	ftl_rs_buf_free(&output);
	ftl_rs_buf_free(&message);
}

// The payload of len bytes of a kind: text-like (0), zeros (1) or pseudo-random bytes (2)
static void fill_payload(unsigned char *buf, const size_t len, const int kind)
{
	uint32_t x = 1 + (uint32_t)kind;
	for(size_t i = 0; i < len; i++)
	{
		x = x * 1103515245u + 12345u;
		const uint32_t r = x >> 16;
		if(kind == 0)
			buf[i] = r % 6 == 0 ? ' ' : (unsigned char)('a' + r % 26);
		else if(kind == 1)
			buf[i] = 0;
		else
			buf[i] = (unsigned char)r;
	}
}

// The gzip stream that Rust makes of data, in memory of the caller's own
static struct bytes rust_deflate(const unsigned char *data, const size_t len)
{
	ftl_rs_buf out = { NULL, 0, 0 };
	struct bytes stream = { NULL, 0, 0 };
	if(ftl_rs_gzip_deflate(data, len, MTIME, &out))
		append(&stream, out.ptr, out.len);
	ftl_rs_buf_free(&out);
	return stream;
}

// The CRC-32 that the footer of a stream of data holds
static uint32_t crc_of(const unsigned char *data, const size_t len)
{
	return (uint32_t)mz_crc32(MZ_CRC32_INIT, data, len);
}

// A gzip stream from its parts, with the CRC-32 and the ISIZE in the footer
static struct bytes assemble(const unsigned char method, const unsigned char flags,
                             const unsigned char *fields, const size_t fields_len,
                             const unsigned char *body, const size_t body_len,
                             const uint32_t crc, const uint32_t out_size)
{
	struct bytes stream = { NULL, 0, 0 };
	const unsigned char header[10] = { 0x1f, 0x8b, method, flags, 0, 0, 0, 0, 0, 3 };
	unsigned char footer[8];
	for(unsigned int i = 0; i < 4; i++)
	{
		footer[i] = (unsigned char)(crc >> (8 * i));
		footer[4 + i] = (unsigned char)(out_size >> (8 * i));
	}
	append(&stream, header, sizeof(header));
	append(&stream, fields, fields_len);
	append(&stream, body, body_len);
	append(&stream, footer, sizeof(footer));
	return stream;
}

// Keeps stream as a seed to mutate. The seed takes over the memory of stream
static void add_seed(const char *name, struct bytes stream)
{
	struct seed *grown = realloc(seeds, (seed_count + 1) * sizeof(*seeds));
	if(grown == NULL)
		out_of_memory();
	seeds = grown;
	seeds[seed_count].name = name;
	seeds[seed_count].stream = stream;
	seed_count++;
}

// Each payload, deflated by C and by Rust, has to inflate back to itself on both sides
static void round_trips(void)
{
	static const size_t lengths[] = {
		0, 1, 2, 3, 7, 15, 16, 17, 100, 255, 256, 257, 1000, 4096, 65535, 65536, 70000, 300000
	};
	char label[160];
	for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
		for(int kind = 0; kind < 3; kind++)
		{
			const size_t len = lengths[i];
			unsigned char *data = malloc(len > 0 ? len : 1);
			if(data == NULL)
				out_of_memory();
			fill_payload(data, len, kind);
			// C rejects an ISIZE of 0, so an empty payload is compared like any other
			// stream but does not have to round trip
			const unsigned char *expected = len > 0 ? data : NULL;

			unsigned char *c_stream = NULL;
			mz_ulong c_len = 0;
			snprintf(label, sizeof(label), "C deflate of %zu bytes, kind %d", len, kind);
			if(deflate_buffer_c(data, len, &c_stream, &c_len))
			{
				compare_stream(label, c_stream, c_len, expected, len);
				free(c_stream);
			}
			else
				difference(label, "deflate failed", "not run");

			struct bytes rust = rust_deflate(data, len);
			snprintf(label, sizeof(label), "Rust deflate of %zu bytes, kind %d", len, kind);
			compare_stream(label, rust.data, rust.len, expected, len);
			free_bytes(&rust);
			free(data);
		}
}

// Appends the FEXTRA field of the generated streams: XLEN and 5 bytes
static void append_extra(struct bytes *fields)
{
	static const unsigned char extra[] = { 0, 1, 'x', 'y', 'z' };
	const unsigned char xlen[2] = { sizeof(extra), 0 };
	append(fields, xlen, sizeof(xlen));
	append(fields, extra, sizeof(extra));
}

// Every combination of FEXTRA, FNAME and FCOMMENT over the Rust body of a payload,
// with valid footers. The streams become seeds for the mutations
static void header_variants(void)
{
	static const unsigned char name[] = "name.txt";
	static const unsigned char comment[] = "a comment";
	static const size_t lengths[] = { 300, 5000 };
	char label[160];
	for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
	{
		const size_t len = lengths[i];
		unsigned char *data = malloc(len);
		if(data == NULL)
			out_of_memory();
		fill_payload(data, len, 0);
		struct bytes rust = rust_deflate(data, len);
		// Without its header and footer, the Rust stream is the DEFLATE body
		const unsigned char *body = rust.data + 10;
		const size_t body_len = rust.len - 18;
		for(unsigned int combo = 0; combo < 8; combo++)
		{
			unsigned char flags = GZIP_FTEXT;
			struct bytes fields = { NULL, 0, 0 };
			if(combo & 1)
			{
				flags |= GZIP_FEXTRA;
				append_extra(&fields);
			}
			if(combo & 2)
			{
				flags |= GZIP_FNAME;
				append(&fields, name, sizeof(name));
			}
			if(combo & 4)
			{
				flags |= GZIP_FCOMMENT;
				append(&fields, comment, sizeof(comment));
			}
			struct bytes stream = assemble(8, flags, fields.data, fields.len, body, body_len,
			                               crc_of(data, len), (uint32_t)len);
			snprintf(label, sizeof(label), "header variant 0x%02x of %zu bytes", (unsigned int)flags, len);
			compare_stream(label, stream.data, stream.len, data, len);
			add_seed("header variant", stream);
			free_bytes(&fields);
		}
		free_bytes(&rust);
		free(data);
	}
}

// Compares one stream that is not a round trip, and frees it
static void check_stream(const char *label, struct bytes stream)
{
	compare_stream(label, stream.data, stream.len, NULL, 0);
	free_bytes(&stream);
}

// Streams with one header or body fault each. C and Rust must reject each one the same way
static void invalid_headers(void)
{
	static const unsigned char data[] = "hello world";
	static const unsigned char zeros[] = { 0, 0 };
	static const unsigned char abc[] = "abc";
	static const unsigned char extra_max[] = { 0xff, 0xff };
	static const unsigned char reserved[] = { 0x07 };
	const size_t len = sizeof(data) - 1;
	const uint32_t crc = crc_of(data, len);
	const uint32_t size = (uint32_t)len;
	struct bytes rust = rust_deflate(data, len);
	const unsigned char *body = rust.data + 10;
	const size_t body_len = rust.len - 18;

	check_stream("invalid header: FHCRC set",
	             assemble(8, GZIP_FTEXT | GZIP_FHCRC, zeros, sizeof(zeros), body, body_len, crc, size));
	check_stream("invalid header: method 9", assemble(9, GZIP_FTEXT, NULL, 0, body, body_len, crc, size));
	check_stream("invalid header: FNAME without a terminator",
	             assemble(8, GZIP_FNAME, abc, sizeof(abc) - 1, NULL, 0, 0, 1));
	check_stream("invalid header: FEXTRA with XLEN 65535",
	             assemble(8, GZIP_FEXTRA, extra_max, sizeof(extra_max), body, body_len, crc, size));
	check_stream("invalid footer: wrong CRC-32",
	             assemble(8, GZIP_FTEXT, NULL, 0, body, body_len, crc ^ 1, size));
	check_stream("invalid footer: ISIZE 0", assemble(8, GZIP_FTEXT, NULL, 0, body, body_len, crc, 0));
	check_stream("invalid footer: ISIZE 0x10000001",
	             assemble(8, GZIP_FTEXT, NULL, 0, body, body_len, crc, 0x10000001u));
	check_stream("invalid footer: ISIZE below the data",
	             assemble(8, GZIP_FTEXT, NULL, 0, body, body_len, crc, size - 1));
	check_stream("invalid footer: ISIZE above the data",
	             assemble(8, GZIP_FTEXT, NULL, 0, body, body_len, crc, 100));

	struct bytes tail = { NULL, 0, 0 };
	static const unsigned char junk[] = { 1, 2, 3 };
	append(&tail, body, body_len);
	append(&tail, junk, sizeof(junk));
	check_stream("invalid body: bytes after the DEFLATE stream",
	             assemble(8, GZIP_FTEXT, NULL, 0, tail.data, tail.len, crc, size));
	free_bytes(&tail);

	check_stream("invalid body: truncated DEFLATE stream",
	             assemble(8, GZIP_FTEXT, NULL, 0, body, body_len / 2, crc, size));
	check_stream("invalid body: reserved DEFLATE block",
	             assemble(8, GZIP_FTEXT, NULL, 0, reserved, sizeof(reserved), 0, 1));
	free_bytes(&rust);
}

// Writes len bytes of data to the file at path. Returns false on an error
static bool write_file(const char *path, const unsigned char *data, const size_t len)
{
	const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if(fd < 0)
		return false;
	const bool ok = write_all(fd, data, len);
	return close(fd) == 0 && ok;
}

// Whether the file at path holds exactly the len bytes of data
static bool file_holds(const char *path, const unsigned char *data, const size_t len)
{
	struct bytes held = { NULL, 0, 0 };
	const bool ok = read_file(path, &held) && same_bytes(held.data, held.len, data, len);
	free_bytes(&held);
	return ok;
}

// The file functions of src/zip/gzip.c. With HAVE_FTL_RS they run on Rust, so the
// two directions cross the implementations: a file that deflate_file() wrote has to
// pass the C reference, and a file that deflate_buffer_c() wrote has to come back
// through inflate_file(). Every payload has to come back byte for byte
static void file_wrappers(void)
{
	static const size_t lengths[] = { 1, 100, 70000 };
	char dir[] = "/tmp/ftl-rust-compare-gzip-XXXXXX";
	if(mkdtemp(dir) == NULL)
	{
		difference("file wrappers", "a temporary directory", "cannot create one");
		return;
	}
	char payload_path[PATH_MAX];
	char rust_path[PATH_MAX];
	char c_path[PATH_MAX];
	char back_path[PATH_MAX];
	snprintf(payload_path, sizeof(payload_path), "%s/payload", dir);
	snprintf(rust_path, sizeof(rust_path), "%s/rust.gz", dir);
	snprintf(c_path, sizeof(c_path), "%s/c.gz", dir);
	snprintf(back_path, sizeof(back_path), "%s/back", dir);
	char label[160];
	for(size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
		for(int kind = 0; kind < 3; kind++)
		{
			const size_t len = lengths[i];
			unsigned char *data = malloc(len);
			if(data == NULL)
				out_of_memory();
			fill_payload(data, len, kind);
			snprintf(label, sizeof(label), "file wrappers, %zu bytes, kind %d", len, kind);

			if(!write_file(payload_path, data, len))
				difference(label, "the payload file", "cannot be written");
			else
			{
				// deflate_file(), then the C reference and inflate_file() on its file
				if(!deflate_file(payload_path, rust_path, false))
					difference(label, "deflate_file() of the payload", "failed");
				else
				{
					struct bytes stream = { NULL, 0, 0 };
					if(read_file(rust_path, &stream))
						compare_stream(label, stream.data, stream.len, data, len);
					else
						difference(label, "the file deflate_file() wrote", "cannot be read");
					free_bytes(&stream);
					if(!inflate_file(rust_path, back_path, false) || !file_holds(back_path, data, len))
						difference(label, "the original payload", "inflate_file() did not give it back");
				}

				// deflate_buffer_c(), then inflate_file() on its file
				unsigned char *c_stream = NULL;
				mz_ulong c_len = 0;
				if(!deflate_buffer_c(data, len, &c_stream, &c_len))
					difference(label, "deflate_buffer_c() of the payload", "failed");
				else
				{
					if(!write_file(c_path, c_stream, c_len))
						difference(label, "the C stream", "cannot be written");
					else if(!inflate_file(c_path, back_path, false) || !file_holds(back_path, data, len))
						difference(label, "the original payload", "inflate_file() did not give it back");
					free(c_stream);
				}
			}
			free(data);
		}

	unlink(payload_path);
	unlink(rust_path);
	unlink(c_path);
	unlink(back_path);
	rmdir(dir);
}

// Every prefix of the short seeds. Each prefix must be accepted or rejected the same way
static void truncations(void)
{
	char label[PATH_MAX + 96];
	for(size_t s = 0; s < seed_count; s++)
	{
		const struct seed *seed = &seeds[s];
		if(seed->stream.len > MAX_PREFIX_SEED)
			continue;
		for(size_t cut = 0; cut < seed->stream.len; cut++)
		{
			snprintf(label, sizeof(label), "seed %zu (%s) cut to %zu of %zu bytes",
			         s, seed->name, cut, seed->stream.len);
			compare_stream(label, seed->stream.data, cut, NULL, 0);
		}
	}
}

// xorshift64*: the same sequence on every run
static uint64_t next_random(void)
{
	rng_state ^= rng_state >> 12;
	rng_state ^= rng_state << 25;
	rng_state ^= rng_state >> 27;
	return rng_state * 0x2545F4914F6CDD1Du;
}

// A number below n, or 0 if n is 0
static size_t random_below(const size_t n)
{
	return n == 0 ? 0 : (size_t)(next_random() % n);
}

// Writes value as 4 little-endian bytes at at, if they lie within b
static void put(struct bytes *b, const size_t at, const uint32_t value)
{
	if(at > b->len || b->len - at < 4)
		return;
	for(unsigned int i = 0; i < 4; i++)
		b->data[at + i] = (unsigned char)(value >> (8 * i));
}

// A copy of seed with one change: bit flips, a truncation, a size or flag field
// set to an edge value, random bytes, or bytes inserted or deleted
static struct bytes mutate(const struct bytes *seed)
{
	struct bytes m = { NULL, 0, 0 };
	append(&m, seed->data, seed->len);
	const size_t len = seed->len;
	switch(random_below(5))
	{
	case 0:
		for(size_t flips = 1 + random_below(4); flips > 0 && len > 0; flips--)
			m.data[random_below(len)] ^= (unsigned char)(1u << random_below(8));
		break;
	case 1:
		m.len = random_below(len + 1);
		break;
	case 2:
	{
		// The method, flags, XLEN, ISIZE and CRC-32 fields
		static const uint32_t edges[] = {
			0, 1, 0x7f, 0x80, 0xffff, 0x0fffffff, 0x10000000, 0x10000001, 0xffffffff
		};
		const size_t fields[] = {
			2, 3, 10, len >= 4 ? len - 4 : len, len >= 8 ? len - 8 : len
		};
		const uint32_t value = random_below(2) == 0
		                       ? edges[random_below(sizeof(edges) / sizeof(edges[0]))]
		                       : (uint32_t)next_random();
		put(&m, fields[random_below(sizeof(fields) / sizeof(fields[0]))], value);
		break;
	}
	case 3:
		m.len = 0;
		for(size_t n = random_below(64); n > 0; n--)
		{
			const unsigned char byte = (unsigned char)next_random();
			append(&m, &byte, 1);
		}
		if(m.len >= 3 && random_below(2) == 0)
			memcpy(m.data, "\x1f\x8b\x08", 3);
		break;
	default:
	{
		const size_t at = random_below(len + 1);
		struct bytes out = { NULL, 0, 0 };
		append(&out, m.data, at);
		if(random_below(2) == 0)
		{
			for(size_t n = 1 + random_below(8); n > 0; n--)
			{
				const unsigned char byte = (unsigned char)next_random();
				append(&out, &byte, 1);
			}
			if(at < len)
				append(&out, m.data + at, len - at);
		}
		else
		{
			size_t end = at + 1 + random_below(16);
			if(end > len)
				end = len;
			if(end < len)
				append(&out, m.data + end, len - end);
		}
		free_bytes(&m);
		m = out;
		break;
	}
	}
	return m;
}

// Mutated copies of the seeds, chosen by the same sequence on every run
static void mutations(void)
{
	char label[PATH_MAX + 96];
	rng_state = 0x0123456789ABCDEFu;
	for(unsigned int i = 0; i < MUTATIONS && seed_count > 0; i++)
	{
		const size_t s = random_below(seed_count);
		struct bytes m = mutate(&seeds[s].stream);
		snprintf(label, sizeof(label), "mutation %u of seed %zu (%s)", i, s, seeds[s].name);
		compare_stream(label, m.data, m.len, NULL, 0);
		free_bytes(&m);
	}
}

// pihole-FTL rust-compare gzip [file...]: compares C and Rust gzip on the given
// streams, on round trips of C and Rust deflate, on header variants, on invalid
// headers, on the file functions, on truncations and on mutations of the streams.
// Each C inflate runs in a forked child, so a crash in C is reported and is not a
// difference. A rejection the C miniz makes and miniz_oxide does not (see
// is_documented_difference()) is counted as a documented difference
int ftl_rs_compare_gzip(int argc, char *argv[])
{
	for(int i = 0; i < argc; i++)
	{
		struct bytes stream = { NULL, 0, 0 };
		if(!read_file(argv[i], &stream))
		{
			difference(argv[i], "cannot read the file", "not compared");
			free_bytes(&stream);
			continue;
		}
		compare_stream(argv[i], stream.data, stream.len, NULL, 0);
		add_seed(argv[i], stream);
	}
	round_trips();
	header_variants();
	invalid_headers();
	file_wrappers();
	truncations();
	mutations();

	for(size_t s = 0; s < seed_count; s++)
		free_bytes(&seeds[s].stream);
	free(seeds);
	seeds = NULL;
	seed_count = 0;

	if(differences > MAX_SHOWN)
		printf("... %u more differences not shown\n", differences - MAX_SHOWN);
	if(crashes > 0)
		printf("rust-compare gzip: C crashed on %u inputs (C bugs, not counted as differences)\n", crashes);
	printf("rust-compare gzip: documented differences: %u (C miniz accepts incomplete code-length tables)\n", documented);
	printf("rust-compare gzip: %u inputs, %u differences\n", inputs, differences);
	return differences == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
