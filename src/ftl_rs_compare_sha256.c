/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare sha256: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <nettle/sha2.h>
#include <nettle/version.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ftl_rs.h"

// The C file hash of src/files.c (nettle), the reference for the Rust version
bool sha256sum_c(const char *path, uint8_t checksum[SHA256_DIGEST_SIZE], const bool skip_end);
// Hex text of a digest (src/config/password.c)
void sha256_raw_to_hex(uint8_t *data, char *buffer);

// Buffer inputs: every length up to MAX_SHORT_LEN, then the lengths around the
// page sizes and 1 MiB. Each buffer is a prefix of one LCG stream, so every run
// hashes the same bytes
#define MAX_SHORT_LEN 4160u
#define MIB (1024u * 1024u)
static const size_t long_lengths[] = {
	4095, 4096, 4097, 8191, 8192, 8193, 65535, 65536, 65537, MIB - 1, MIB, MIB + 1
};

// Differences after this many are counted but not printed
#define MAX_DIFFERENCES_SHOWN 50

static unsigned int inputs = 0;
static unsigned int differences = 0;

// Fills buf with the first len bytes of a fixed LCG stream
static void fill_pattern(uint8_t *buf, const size_t len)
{
	uint32_t x = 1;
	for(size_t i = 0; i < len; i++)
	{
		x = x * 1103515245u + 12345u;
		buf[i] = (uint8_t)(x >> 16);
	}
}

// Counts a difference and prints it while the cap allows
static void difference(const char *input, const char *c_result, const char *rust_result)
{
	differences++;
	if(differences <= MAX_DIFFERENCES_SHOWN)
		printf("difference: %s\n  C:    %s\n  Rust: %s\n", input, c_result, rust_result);
}

// Hashes len bytes with nettle and with the Rust library
static void compare_buffer(const uint8_t *data, const size_t len)
{
	uint8_t c[SHA256_DIGEST_SIZE], rust[SHA256_DIGEST_SIZE];
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, len, data);
#if NETTLE_VERSION_MAJOR >= 4
	sha256_digest(&ctx, c);
#else
	sha256_digest(&ctx, SHA256_DIGEST_SIZE, c);
#endif
	ftl_rs_sha256_buf(data, len, rust);

	inputs++;
	if(memcmp(c, rust, SHA256_DIGEST_SIZE) == 0)
		return;

	char input[64], c_hex[SHA256_DIGEST_SIZE * 2 + 1], rust_hex[SHA256_DIGEST_SIZE * 2 + 1];
	snprintf(input, sizeof(input), "buffer of %zu bytes", len);
	sha256_raw_to_hex(c, c_hex);
	sha256_raw_to_hex(rust, rust_hex);
	difference(input, c_hex, rust_hex);
}

// Hashes a file with both implementations. If neither can open or read it,
// that is the same result and each has logged why. Otherwise both must return
// the same digest: the C side returns true for a file it cannot read, so the
// Rust error shows up as a difference here
static void compare_file(const char *path, const bool skip_end)
{
	uint8_t c[SHA256_DIGEST_SIZE], rust[SHA256_DIGEST_SIZE];
	const bool c_ok = sha256sum_c(path, c, skip_end);
	const int rust_err = ftl_rs_sha256_file(path, skip_end, rust);

	inputs++;
	if(!c_ok && rust_err != 0)
		return;
	if(c_ok && rust_err == 0 && memcmp(c, rust, SHA256_DIGEST_SIZE) == 0)
		return;

	char input[PATH_MAX + 64];
	char c_text[SHA256_DIGEST_SIZE * 2 + 1];
	char rust_text[SHA256_DIGEST_SIZE * 2 + 1 + 64];
	snprintf(input, sizeof(input), "file %s, skip_end=%s", path, skip_end ? "true" : "false");
	if(c_ok)
		sha256_raw_to_hex(c, c_text);
	else
		snprintf(c_text, sizeof(c_text), "failed (see the log above)");
	if(rust_err == 0)
		sha256_raw_to_hex(rust, rust_text);
	else
		snprintf(rust_text, sizeof(rust_text), "%s failed: %s",
		         rust_err > 0 ? "open" : "read", strerror(abs(rust_err)));
	difference(input, c_text, rust_text);
}

// A file with skip_end off and on
static void compare_file_both_ways(const char *path)
{
	compare_file(path, false);
	compare_file(path, true);
}

// pihole-FTL rust-compare sha256 [file...]: compares the buffers, then the
// given files, or /proc/self/exe and an empty file if no file is given
int ftl_rs_compare_sha256(int argc, char *argv[])
{
	const size_t max_len = MIB + 1;
	uint8_t *data = malloc(max_len);
	if(data == NULL)
	{
		printf("rust-compare sha256: out of memory\n");
		return EXIT_FAILURE;
	}
	fill_pattern(data, max_len);
	for(size_t len = 0; len <= MAX_SHORT_LEN; len++)
		compare_buffer(data, len);
	for(size_t i = 0; i < sizeof(long_lengths) / sizeof(long_lengths[0]); i++)
		compare_buffer(data, long_lengths[i]);
	free(data);

	char empty[] = "/tmp/ftl-rs-sha256-XXXXXX";
	const int fd = mkstemp(empty);
	if(fd < 0)
	{
		printf("rust-compare sha256: cannot create an empty file: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	close(fd);

	if(argc > 0)
		for(int i = 0; i < argc; i++)
			compare_file_both_ways(argv[i]);
	else
	{
		compare_file_both_ways("/proc/self/exe");
		compare_file_both_ways(empty);
	}
	unlink(empty);

	if(differences > MAX_DIFFERENCES_SHOWN)
		printf("... %u more differences not shown\n", differences - MAX_DIFFERENCES_SHOWN);
	printf("rust-compare sha256: %u inputs, %u differences\n", inputs, differences);
	return differences == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
