#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Include the implementation directly so the tests can exercise the same
// private constants as gzip.c.
#include "zip/gzip.c"

#undef calloc
#undef free
#undef fprintf
#undef fopen
#undef printf
#undef realloc
#undef snprintf
#undef strlen
#undef strcmp
#undef strstr
#undef vfprintf
#undef vsnprintf
#undef memcmp
#undef memcpy
#undef memmove
#undef memset

#define GZIP_FLG_FEXTRA 0x04u
#define GZIP_FLG_FNAME 0x08u
#define GZIP_FLG_FCOMMENT 0x10u

static char last_log[512];
static int failures = 0;

struct gzip_test {
	const char *name;
	void (*run)(void);
};

void _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	(void)priority;
	(void)flag;

	va_list args;
	va_start(args, format);
	vsnprintf(last_log, sizeof(last_log), format, args);
	va_end(args);

	fprintf(stderr, "%s\n", last_log);
}

void format_memory_size(char prefix[2], const off_t bytes, double * const formatted)
{
	prefix[0] = '\0';
	prefix[1] = '\0';
	*formatted = (double)bytes;
}

bool FTLfree(void *ptr, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	free(ptr);
	return true;
}

void *FTLcalloc(size_t n, size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return calloc(n, size);
}

void *FTLrealloc(void *ptr, size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return realloc(ptr, size);
}

FILE *FTLfopen(const char *pathname, const char *mode, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return fopen(pathname, mode);
}

int FTLfprintf(FILE *stream, const char *file, const char *func, const int line, const char *format, ...)
{
	(void)file;
	(void)func;
	(void)line;

	va_list args;
	va_start(args, format);
	const int ret = vfprintf(stream, format, args);
	va_end(args);
	return ret;
}

int FTLvfprintf(FILE *stream, const char *file, const char *func, const int line, const char *format, va_list args)
{
	(void)file;
	(void)func;
	(void)line;
	return vfprintf(stream, format, args);
}

int FTLsnprintf(const char *file, const char *func, const int line, char *buffer, const size_t maxlen, const char *format, ...)
{
	(void)file;
	(void)func;
	(void)line;

	va_list args;
	va_start(args, format);
	const int ret = vsnprintf(buffer, maxlen, format, args);
	va_end(args);
	return ret;
}

int FTLvsnprintf(const char *file, const char *func, const int line, char *buffer, const size_t maxlen, const char *format, va_list args)
{
	(void)file;
	(void)func;
	(void)line;
	return vsnprintf(buffer, maxlen, format, args);
}

void *FTLmemset(void *s, const int c, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memset(s, c, n);
}

void *FTLmemcpy(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcpy(dest, src, n);
}

void *FTLmemmove(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memmove(dest, src, n);
}

size_t FTLstrlen(const char *s, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strlen(s);
}

int FTLmemcmp(const void *s1, const void *s2, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcmp(s1, s2, n);
}

struct gzip_blob {
	unsigned char *data;
	mz_ulong size;
};

static void reset_log(void)
{
	last_log[0] = '\0';
}

static void expect(const bool condition, const char *message)
{
	if(condition)
		return;

	fprintf(stderr, "FAIL: %s\n", message);
	failures++;
}

static bool failf(const char *format, ...)
{
	fprintf(stderr, "FAIL: ");
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fputc('\n', stderr);
	failures++;
	return false;
}

static void write_le32(unsigned char *dest, uint32_t value)
{
	for(unsigned int i = 0; i < 4; i++)
		dest[i] = (unsigned char)((value >> (i * 8)) & 0xffu);
}

static bool build_gzip(const unsigned char *payload, const mz_ulong payload_size,
                       const unsigned char flags,
                       const unsigned char *extra, const uint16_t extra_size,
                       const char *name, const char *comment,
                       struct gzip_blob *blob)
{
	blob->data = NULL;
	blob->size = 0;

	mz_ulong zlib_size = compressBound(payload_size);
	unsigned char *zlib_stream = malloc(zlib_size);
	if(zlib_stream == NULL)
		return failf("failed to allocate zlib stream");

	int ret = compress2(zlib_stream, &zlib_size, payload, payload_size, Z_BEST_COMPRESSION);
	if(ret != Z_OK)
	{
		free(zlib_stream);
		return failf("compress2 failed: %s", zError(ret));
	}
	if(zlib_size < 6)
	{
		free(zlib_stream);
		return failf("compressed stream is unexpectedly short");
	}

	size_t optional_size = 0;
	if(flags & GZIP_FLG_FEXTRA)
		optional_size += 2u + extra_size;
	if(flags & GZIP_FLG_FNAME)
		optional_size += strlen(name != NULL ? name : "") + 1u;
	if(flags & GZIP_FLG_FCOMMENT)
		optional_size += strlen(comment != NULL ? comment : "") + 1u;

	const mz_ulong raw_deflate_size = zlib_size - 6u;
	const size_t total_size = GZIP_HEADER_SIZE + optional_size + raw_deflate_size + GZIP_FOOTER_SIZE;
	unsigned char *gzip_stream = calloc(total_size, sizeof(*gzip_stream));
	if(gzip_stream == NULL)
	{
		free(zlib_stream);
		return failf("failed to allocate gzip stream");
	}

	unsigned char header[GZIP_HEADER_SIZE] = {
		0x1f, 0x8b, 0x08, flags, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03
	};
	memcpy(gzip_stream, header, sizeof(header));

	size_t offset = GZIP_HEADER_SIZE;
	if(flags & GZIP_FLG_FEXTRA)
	{
		gzip_stream[offset++] = (unsigned char)(extra_size & 0xffu);
		gzip_stream[offset++] = (unsigned char)(extra_size >> 8);
		if(extra_size > 0)
		{
			memcpy(gzip_stream + offset, extra, extra_size);
			offset += extra_size;
		}
	}
	if(flags & GZIP_FLG_FNAME)
	{
		const char *field = name != NULL ? name : "";
		const size_t field_size = strlen(field) + 1u;
		memcpy(gzip_stream + offset, field, field_size);
		offset += field_size;
	}
	if(flags & GZIP_FLG_FCOMMENT)
	{
		const char *field = comment != NULL ? comment : "";
		const size_t field_size = strlen(field) + 1u;
		memcpy(gzip_stream + offset, field, field_size);
		offset += field_size;
	}

	memcpy(gzip_stream + offset, zlib_stream + 2, raw_deflate_size);
	offset += raw_deflate_size;

	const uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, payload, payload_size);
	write_le32(gzip_stream + offset, crc);
	offset += sizeof(uint32_t);
	write_le32(gzip_stream + offset, (uint32_t)payload_size);
	offset += sizeof(uint32_t);

	free(zlib_stream);

	if(offset != total_size)
	{
		free(gzip_stream);
		return failf("internal gzip builder size mismatch");
	}

	blob->data = gzip_stream;
	blob->size = (mz_ulong)total_size;
	return true;
}

static void free_blob(struct gzip_blob *blob)
{
	free(blob->data);
	blob->data = NULL;
	blob->size = 0;
}

// Test-vector export (--export-vectors DIR). Every input handed to FTL's
// inflate_buffer() is written to DIR as a binary file and its observed result is
// recorded for DIR/manifest.json. Tests still run isolated in children: each child
// writes its records to a hidden part file, and the parent merges the parts in
// test-table order so the manifest is deterministic.
#define EXPORT_MODULE "gzip"
#define EXPORT_GENERATOR "test/gzip_regression.c"
#define EXPORT_OP "inflate_buffer"
#define EXPORT_MAX_VECTORS_PER_TEST 16u
#define EXPORT_PATH_MAX 1024u

struct export_record {
	char file[128];
	bool rejected;
	mz_ulong output_size;
	char output_sha256[65];
	bool has_c_log;
	char c_log[sizeof(last_log)];
};

static const char *export_dir = NULL;
static const char *current_test = "";
static struct export_record export_records[EXPORT_MAX_VECTORS_PER_TEST];
static size_t export_count = 0;

static const uint32_t sha256_k[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
	0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
	0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
	0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
	0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
	0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
	0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static uint32_t sha256_rotr(const uint32_t x, const unsigned int n)
{
	return (x >> n) | (x << (32u - n));
}

static void sha256_block(uint32_t state[8], const unsigned char block[64])
{
	uint32_t w[64];
	for(unsigned int i = 0; i < 16; i++)
		w[i] = ((uint32_t)block[4 * i] << 24) | ((uint32_t)block[4 * i + 1] << 16) |
		       ((uint32_t)block[4 * i + 2] << 8) | (uint32_t)block[4 * i + 3];
	for(unsigned int i = 16; i < 64; i++)
	{
		const uint32_t s0 = sha256_rotr(w[i - 15], 7) ^ sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
		const uint32_t s1 = sha256_rotr(w[i - 2], 17) ^ sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
	for(unsigned int i = 0; i < 64; i++)
	{
		const uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
		const uint32_t ch = (e & f) ^ (~e & g);
		const uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
		const uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
		const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		const uint32_t t2 = S0 + maj;
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
	state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

// SHA-256 (FIPS 180-4) of a buffer. Only used to fingerprint decompressed payloads
// in the export manifest; the harness links no crypto library.
static void sha256_digest(const unsigned char *data, const size_t len, unsigned char digest[32])
{
	uint32_t state[8] = {
		0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
	};

	size_t offset = 0;
	for(; len - offset >= 64; offset += 64)
		sha256_block(state, data + offset);

	// The last one or two blocks: remaining bytes, 0x80, zero padding, then the
	// message length in bits as a big-endian 64-bit integer
	unsigned char tail[128];
	memset(tail, 0, sizeof(tail));
	const size_t rest = len - offset;
	if(rest > 0)
		memcpy(tail, data + offset, rest);
	tail[rest] = 0x80u;
	const size_t tail_len = (rest + 1u + 8u <= 64u) ? 64u : 128u;
	const uint64_t bits = (uint64_t)len * 8u;
	for(unsigned int i = 0; i < 8; i++)
		tail[tail_len - 1u - i] = (unsigned char)(bits >> (8u * i));
	for(size_t pos = 0; pos < tail_len; pos += 64)
		sha256_block(state, tail + pos);

	for(unsigned int i = 0; i < 8; i++)
		for(unsigned int j = 0; j < 4; j++)
			digest[4 * i + j] = (unsigned char)(state[i] >> (24u - 8u * j));
}

static void sha256_hex(const unsigned char *data, const size_t len, char hex[65])
{
	static const char digits[] = "0123456789abcdef";
	unsigned char digest[32];
	sha256_digest(data, len, digest);
	for(unsigned int i = 0; i < sizeof(digest); i++)
	{
		hex[2 * i] = digits[digest[i] >> 4];
		hex[2 * i + 1] = digits[digest[i] & 0x0fu];
	}
	hex[64] = '\0';
}

static bool export_part_path(char path[EXPORT_PATH_MAX], const char *test_name)
{
	return snprintf(path, EXPORT_PATH_MAX, "%s/.%s.part", export_dir, test_name) < (int)EXPORT_PATH_MAX;
}

static void export_json_string(FILE *out, const char *s)
{
	fputc('"', out);
	for(const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++)
	{
		switch(*p)
		{
		case '"': fputs("\\\"", out); break;
		case '\\': fputs("\\\\", out); break;
		case '\n': fputs("\\n", out); break;
		case '\r': fputs("\\r", out); break;
		case '\t': fputs("\\t", out); break;
		default:
			if(*p < 0x20u)
				fprintf(out, "\\u%04x", (unsigned int)*p);
			else
				fputc(*p, out);
			break;
		}
	}
	fputc('"', out);
}

// Called for every inflate_buffer() call made by inflate_copy(). The input is
// written as it was handed to FTL (before the scratch copy is mutated).
static void export_record_inflate(const unsigned char *data, const mz_ulong size,
                                  const bool success, const unsigned char *output,
                                  const mz_ulong output_size, const bool log_asserted)
{
	if(export_count >= EXPORT_MAX_VECTORS_PER_TEST)
	{
		failf("%s: more than %u export vectors", current_test, EXPORT_MAX_VECTORS_PER_TEST);
		return;
	}

	struct export_record *rec = &export_records[export_count++];
	memset(rec, 0, sizeof(*rec));
	snprintf(rec->file, sizeof(rec->file), "%s-%02lu.gz", current_test, (unsigned long)export_count);

	rec->rejected = !success;
	if(success)
	{
		rec->output_size = output_size;
		sha256_hex(output, output_size, rec->output_sha256);
	}
	else if(log_asserted)
	{
		// Only the failure path is checked against a log string by the harness
		rec->has_c_log = true;
		snprintf(rec->c_log, sizeof(rec->c_log), "%s", last_log);
	}

	char path[EXPORT_PATH_MAX];
	if(snprintf(path, sizeof(path), "%s/%s", export_dir, rec->file) >= (int)sizeof(path))
	{
		failf("export path too long: %s", rec->file);
		return;
	}
	FILE *out = fopen(path, "wb");
	if(out == NULL)
	{
		failf("cannot create %s: %s", path, strerror(errno));
		return;
	}
	const size_t written = fwrite(data, 1, size, out);
	const int closed = fclose(out);
	if(written != size || closed != 0)
		failf("cannot write %s: %s", path, strerror(errno));
}

static void export_write_entry(FILE *out, const char *test_name, const struct export_record *rec)
{
	fputs("    {\n      \"file\": ", out);
	export_json_string(out, rec->file);
	fputs(",\n      \"test\": ", out);
	export_json_string(out, test_name);
	fputs(",\n      \"op\": \"" EXPORT_OP "\",\n      \"args\": {},\n      \"expect\": {\n        \"rejected\": ", out);
	fputs(rec->rejected ? "true" : "false", out);
	if(rec->rejected)
	{
		if(rec->has_c_log)
		{
			fputs(",\n        \"c_log\": ", out);
			export_json_string(out, rec->c_log);
		}
	}
	else
	{
		fprintf(out, ",\n        \"output_size\": %lu", (unsigned long)rec->output_size);
		fputs(",\n        \"output_sha256\": ", out);
		export_json_string(out, rec->output_sha256);
	}
	fputs("\n      }\n    }", out);
}

// Writes this test's records as comma-separated JSON objects (no trailing newline)
static void export_write_part(const char *test_name)
{
	char path[EXPORT_PATH_MAX];
	if(!export_part_path(path, test_name))
	{
		failf("export path too long for %s", test_name);
		return;
	}
	FILE *out = fopen(path, "wb");
	if(out == NULL)
	{
		failf("cannot create %s: %s", path, strerror(errno));
		return;
	}
	for(size_t i = 0; i < export_count; i++)
	{
		if(i > 0)
			fputs(",\n", out);
		export_write_entry(out, test_name, &export_records[i]);
	}
	if(fclose(out) != 0)
		failf("cannot write %s: %s", path, strerror(errno));
}

static bool inflate_copy(const unsigned char *data, const mz_ulong size,
                         unsigned char **output, mz_ulong *output_size,
                         const bool log_asserted)
{
	unsigned char *scratch = malloc(size);
	if(scratch == NULL)
		return failf("failed to allocate mutable gzip input");

	memcpy(scratch, data, size);
	*output = NULL;
	*output_size = 0;
	const bool success = inflate_buffer(scratch, size, output, output_size);
	if(export_dir != NULL)
		export_record_inflate(data, size, success, *output, *output_size, log_asserted);
	free(scratch);
	return success;
}

static void expect_inflate_log_contains(const char *expected_log)
{
	if(strstr(last_log, expected_log) != NULL)
		return;

	fprintf(stderr, "FAIL: expected log containing \"%s\", got \"%s\"\n", expected_log, last_log);
	failures++;
}

static void expect_inflate_failure_with_log(const unsigned char *data, const mz_ulong size,
                                            const char *expected_log)
{
	unsigned char *output = NULL;
	mz_ulong output_size = 0;

	reset_log();
	const bool success = inflate_copy(data, size, &output, &output_size, true);
	free(output);

	expect(!success, "inflate_buffer rejects invalid input");
	if(!success)
		expect_inflate_log_contains(expected_log);
}

static void expect_inflate_success_payload(const struct gzip_blob *blob,
                                           const unsigned char *payload,
                                           const mz_ulong payload_size)
{
	unsigned char *output = NULL;
	mz_ulong output_size = 0;

	reset_log();
	const bool success = inflate_copy(blob->data, blob->size, &output, &output_size, false);
	if(!success)
	{
		free(output);
		failf("inflate_buffer rejected a valid gzip stream: %s", last_log);
		return;
	}
	if(output_size != payload_size)
	{
		free(output);
		failf("expected %lu output bytes, got %lu",
		      (unsigned long)payload_size, (unsigned long)output_size);
		return;
	}
	expect(memcmp(output, payload, payload_size) == 0, "inflated payload matches");

	free(output);
}

static void test_short_stream_is_rejected(void)
{
	unsigned char data[1] = { 0x1f };
	expect_inflate_failure_with_log(data, sizeof(data), "This is not a valid GZIP stream");
}

static void test_extra_field_overlapping_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FEXTRA
	};
	data[GZIP_HEADER_SIZE] = 1u;
	data[GZIP_HEADER_SIZE + 1u] = 0u;

	expect_inflate_failure_with_log(data, sizeof(data), "Invalid GZIP header");
}

static void test_name_field_starting_in_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FNAME
	};

	expect_inflate_failure_with_log(data, sizeof(data), "GZIP file name field overruns into the footer");
}

static void test_name_field_missing_nul_before_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + 2u + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FNAME
	};
	data[GZIP_HEADER_SIZE] = 'n';
	data[GZIP_HEADER_SIZE + 1u] = 'm';

	expect_inflate_failure_with_log(data, sizeof(data), "File name is missing or invalid in GZIP header");
}

static void test_name_field_terminator_in_footer_is_rejected(void)
{
	const size_t size = 40u;
	const size_t nul_at = 39u;
	unsigned char *gz = calloc(1, size);
	expect(gz != NULL, "crafted gzip allocation succeeds");
	if(gz == NULL)
		return;

	gz[0] = 0x1f;
	gz[1] = 0x8b;
	gz[2] = 0x08;
	gz[3] = GZIP_FLG_FNAME;
	gz[8] = 0x02;
	gz[9] = 0x03;

	memset(gz + GZIP_HEADER_SIZE, 'A', size - GZIP_HEADER_SIZE);
	gz[nul_at] = 0x00;

	const size_t new_size = size - (nul_at + 1u - GZIP_HEADER_SIZE);
	write_le32(gz + new_size - 4u, 1u);

	expect_inflate_failure_with_log(gz, size, "File name is missing or invalid in GZIP header");

	free(gz);
}

static void test_comment_field_starting_in_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FCOMMENT
	};

	expect_inflate_failure_with_log(data, sizeof(data), "GZIP file comment field overruns into the footer");
}

static void test_comment_field_missing_nul_before_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + 2u + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FCOMMENT
	};
	data[GZIP_HEADER_SIZE] = 'c';
	data[GZIP_HEADER_SIZE + 1u] = 'm';

	expect_inflate_failure_with_log(data, sizeof(data), "File comment is missing or invalid in GZIP header");
}

static void test_crc32_high_bit_decompresses(void)
{
	static const unsigned char payload[] = "test";
	const uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, payload, sizeof(payload) - 1u);
	if((crc & 0x80000000u) == 0)
	{
		failf("test payload does not exercise the CRC32 high bit");
		return;
	}

	struct gzip_blob blob;
	if(!build_gzip(payload, sizeof(payload) - 1u, 0, NULL, 0, NULL, NULL, &blob))
		return;

	expect_inflate_success_payload(&blob, payload, sizeof(payload) - 1u);
	free_blob(&blob);
}

static void test_empty_optional_fields_decompress(void)
{
	static const unsigned char payload[] = "payload with optional fields";
	static const unsigned char extra[] = { 0x70, 0x69 };

	struct gzip_blob blob;
	if(!build_gzip(payload, sizeof(payload) - 1u,
	               GZIP_FLG_FEXTRA | GZIP_FLG_FNAME | GZIP_FLG_FCOMMENT,
	               extra, sizeof(extra), "", "", &blob))
		return;

	expect_inflate_success_payload(&blob, payload, sizeof(payload) - 1u);
	free_blob(&blob);
}

static const struct gzip_test tests[] = {
	{ "short_stream_is_rejected", test_short_stream_is_rejected },
	{ "extra_field_overlapping_footer_is_rejected", test_extra_field_overlapping_footer_is_rejected },
	{ "name_field_starting_in_footer_is_rejected", test_name_field_starting_in_footer_is_rejected },
	{ "name_field_missing_nul_before_footer_is_rejected", test_name_field_missing_nul_before_footer_is_rejected },
	{ "name_field_terminator_in_footer_is_rejected", test_name_field_terminator_in_footer_is_rejected },
	{ "comment_field_starting_in_footer_is_rejected", test_comment_field_starting_in_footer_is_rejected },
	{ "comment_field_missing_nul_before_footer_is_rejected", test_comment_field_missing_nul_before_footer_is_rejected },
	{ "crc32_high_bit_decompresses", test_crc32_high_bit_decompresses },
	{ "empty_optional_fields_decompress", test_empty_optional_fields_decompress },
};

static int run_test(const struct gzip_test *test)
{
	failures = 0;
	current_test = test->name;
	export_count = 0;
	test->run();

	if (export_dir != NULL)
		export_write_part(test->name);

	if (failures != 0) {
		fprintf(stderr, "FAIL %s: %d assertion(s) failed\n", test->name, failures);
		return 1;
	}

	printf("PASS %s\n", test->name);
	return 0;
}

static int run_named_test(const char *name)
{
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		if (strcmp(tests[i].name, name) == 0)
			return run_test(&tests[i]);

	fprintf(stderr, "unknown gzip regression test: %s\n", name);
	fprintf(stderr, "available tests:\n");
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		fprintf(stderr, "  %s\n", tests[i].name);

	return 2;
}

// Run a single test in a forked child so a sanitizer abort (or any crash)
// fails only that case instead of taking down the rest of the suite. Named
// cases stay in-process for straightforward debugging.
static int run_test_isolated(const struct gzip_test *test)
{
	fflush(NULL);

	pid_t pid = fork();
	if (pid < 0) {
		// fork() is unavailable - fall back to running in-process. A
		// sanitizer abort would still stop the suite here, but a clean
		// build runs every case.
		return run_test(test);
	}

	if (pid == 0) {
		int rc = run_test(test);
		// _exit() does not flush stdio, so drain the child's PASS/FAIL
		// output (fully buffered when stdout is not a terminal) first.
		fflush(NULL);
		_exit(rc);
	}

	int wstatus = 0;
	while (waitpid(pid, &wstatus, 0) < 0) {
		if (errno != EINTR) {
			fprintf(stderr, "FAIL %s: waitpid failed (%s)\n",
			        test->name, strerror(errno));
			return 1;
		}
	}

	if (WIFEXITED(wstatus))
		return WEXITSTATUS(wstatus) == 0 ? 0 : 1;

	if (WIFSIGNALED(wstatus))
		fprintf(stderr, "FAIL %s: terminated by signal %d\n",
		        test->name, WTERMSIG(wstatus));
	else
		fprintf(stderr, "FAIL %s: abnormal termination\n", test->name);

	return 1;
}

static void list_tests(void)
{
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		printf("%s\n", tests[i].name);
}

// Merges the per-test part files in test-table order into DIR/manifest.json and
// removes them. A test without a part file did not finish (crashed or aborted).
static bool export_write_manifest(void)
{
	char path[EXPORT_PATH_MAX];
	if (snprintf(path, sizeof(path), "%s/manifest.json", export_dir) >= (int)sizeof(path)) {
		fprintf(stderr, "export path too long: %s\n", export_dir);
		return false;
	}
	FILE *out = fopen(path, "wb");
	if (out == NULL) {
		fprintf(stderr, "cannot create %s: %s\n", path, strerror(errno));
		return false;
	}

	bool ok = true;
	bool first = true;
	fputs("{\n  \"module\": \"" EXPORT_MODULE "\",\n  \"generator\": \"" EXPORT_GENERATOR "\",\n  \"vectors\": [\n", out);
	for (size_t t = 0; t < sizeof(tests) / sizeof(tests[0]); t++) {
		char part[EXPORT_PATH_MAX];
		if (!export_part_path(part, tests[t].name)) {
			fprintf(stderr, "export path too long for %s\n", tests[t].name);
			ok = false;
			continue;
		}
		FILE *in = fopen(part, "rb");
		if (in == NULL) {
			fprintf(stderr, "FAIL %s: no vector record (test did not complete)\n", tests[t].name);
			ok = false;
			continue;
		}
		int c = fgetc(in);
		if (c != EOF) {
			if (!first)
				fputs(",\n", out);
			first = false;
			for (; c != EOF; c = fgetc(in))
				fputc(c, out);
		}
		fclose(in);
		unlink(part);
	}
	if (!first)
		fputc('\n', out);
	fputs("  ]\n}\n", out);

	if (fclose(out) != 0) {
		fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
		ok = false;
	}
	return ok;
}

static int run_export(const char *dir)
{
	if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "cannot create %s: %s\n", dir, strerror(errno));
		return 1;
	}
	export_dir = dir;

	// Drop part files left behind by an interrupted earlier run, so a test that
	// crashes this time cannot be recorded with stale data
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		char part[EXPORT_PATH_MAX];
		if (export_part_path(part, tests[i].name))
			unlink(part);
	}

	int status = 0;
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		if (run_test_isolated(&tests[i]) != 0)
			status = 1;

	if (!export_write_manifest())
		status = 1;
	return status;
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--list") == 0) {
		list_tests();
		return 0;
	}

	if (argc > 1 && strcmp(argv[1], "--export-vectors") == 0) {
		if (argc != 3) {
			fprintf(stderr, "usage: %s --export-vectors DIR\n", argv[0]);
			return 2;
		}
		return run_export(argv[2]);
	}

	if (argc > 1) {
		int status = 0;
		for (int i = 1; i < argc; i++)
			if (run_named_test(argv[i]) != 0)
				status = 1;
		return status;
	}

	int status = 0;
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		if (run_test_isolated(&tests[i]) != 0)
			status = 1;

	return status;
}
