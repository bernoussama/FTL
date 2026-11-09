/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare tar: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "zip/tar.h"
#include "ftl_rs.h"

// The C reference (find_file_in_tar_c(), list_files_in_tar_c()) and the Rust
// version (ftl_rs_tar_find(), ftl_rs_tar_list()) run on the same archives:
//   - the archives of test/vectors/tar (run from the repository root)
//   - generated archives: names of 1, 99 and 100 bytes, sizes from 0 to several
//     blocks, one entry or 300, with and without the end blocks
//   - MUTANTS deterministic mutations of those archives (fixed seed)
// Each run of either version is a forked child, so a crash or a hang is seen
// as a crash. A crash of the C reference is a C bug and is not counted as a
// difference. A crash of the Rust version is a difference.
#define VECTOR_DIR "test/vectors/tar"
#define MAX_VECTORS 256
#define MAX_BASES 512
#define MUTANTS 4000
#define MAX_ARCHIVE_BYTES (16u * 1024u * 1024u)
#define MAX_DIFFERENCES_SHOWN 50
#define MAX_SHOWN_LINES 40
#define CHILD_TIMEOUT_S 10

// The ustar layout, as the generator and the mutations write it
#define CMP_BLOCK 512
#define CMP_NAME_LEN 100
#define CMP_SIZE_OFFSET 124
#define CMP_SIZE_LEN 12
#define CMP_MAGIC_OFFSET 257

// Text that is built up: a rendered result, or what a child printed
struct tar_text {
	char *s;
	size_t len;
	size_t cap;
};

// An archive being built or mutated. data is never NULL once reserved.
struct tar_archive {
	uint8_t *data;
	size_t len;
	size_t cap;
};

// An archive that the mutations start from
struct tar_base {
	char what[1024];
	struct tar_archive archive;
};

// What a forked child printed, and how it ended
struct tar_run {
	struct tar_text out;
	bool failed;
	bool signaled;
	int number; // the signal, or the exit status
};

typedef void (*tar_render_fn)(const uint8_t *tar, const size_t len, struct tar_text *out);

static unsigned int inputs = 0;
static unsigned int differences = 0;
static unsigned int c_bugs = 0;
static const char *find_names[16];
static size_t n_find_names = 0;
static char name99[CMP_NAME_LEN];     // 99 'n' and the NUL
static char name100[CMP_NAME_LEN + 1]; // 100 'n' and the NUL: no NUL in the field
static const uint8_t zero_blocks[2 * CMP_BLOCK];
static const size_t sizes[] = { 0, 1, 255, 256, 511, 512, 513, 1023, 1024, 1025, 1536, 2048, 4096, 8193 };
static const size_t name_lens[] = { 1, 99, 100 };
static struct tar_base bases[MAX_BASES];
static size_t n_bases = 0;

static void text_add(struct tar_text *t, const char *s, const size_t len)
{
	if(t->len + len + 1 > t->cap)
	{
		size_t cap = t->cap == 0 ? 256 : t->cap;
		while(t->len + len + 1 > cap)
			cap *= 2;
		char *grown = realloc(t->s, cap);
		if(grown == NULL)
		{
			printf("rust-compare tar: out of memory\n");
			exit(EXIT_FAILURE);
		}
		t->s = grown;
		t->cap = cap;
	}
	memcpy(t->s + t->len, s, len);
	t->len += len;
	t->s[t->len] = '\0';
}

static void text_free(struct tar_text *t)
{
	free(t->s);
	t->len = 0;
	t->cap = 0;
}

static void text_str(struct tar_text *t, const char *s)
{
	text_add(t, s, strlen(s));
}

static void text_num(struct tar_text *t, const size_t n)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%zu", n);
	text_str(t, buf);
}

// A name in quotes: bytes that are not printable ASCII, quotes and backslashes
// are written as \xHH
static void text_name(struct tar_text *t, const char *s, const size_t len)
{
	text_str(t, "\"");
	for(size_t i = 0; i < len; i++)
	{
		const unsigned char c = (unsigned char)s[i];
		if(c >= 0x20 && c < 0x7f && c != '"' && c != '\\')
			text_add(t, &s[i], 1);
		else
		{
			char hex[8];
			snprintf(hex, sizeof(hex), "\\x%02x", c);
			text_str(t, hex);
		}
	}
	text_str(t, "\"");
}

static void text_entry(struct tar_text *t, const char *name, const size_t name_len, const size_t size)
{
	text_str(t, "  entry ");
	text_name(t, name, name_len);
	text_str(t, " size=");
	text_num(t, size);
	text_str(t, "\n");
}

// The offset is written only when the file is found
static void text_find(struct tar_text *t, const char *name, const bool found, const size_t offset, const size_t size)
{
	text_str(t, "find ");
	text_name(t, name, strlen(name));
	if(found)
	{
		text_str(t, " found offset=");
		text_num(t, offset);
	}
	else
		text_str(t, " not found");
	text_str(t, " size=");
	text_num(t, size);
	text_str(t, "\n");
}

// The C reference: the list, then find for each name
static void render_c(const uint8_t *tar, const size_t len, struct tar_text *out)
{
	cJSON *files = list_files_in_tar_c(tar, len);
	const int count = cJSON_GetArraySize(files);
	text_str(out, "list ");
	text_num(out, (size_t)count);
	text_str(out, "\n");
	for(int i = 0; i < count; i++)
	{
		const cJSON *file = cJSON_GetArrayItem(files, i);
		const cJSON *name_item = cJSON_GetObjectItemCaseSensitive(file, "name");
		const cJSON *size_item = cJSON_GetObjectItemCaseSensitive(file, "size");
		if(name_item == NULL || name_item->valuestring == NULL || size_item == NULL)
		{
			text_str(out, "  entry <missing>\n");
			continue;
		}
		text_entry(out, name_item->valuestring, strlen(name_item->valuestring), (size_t)size_item->valuedouble);
	}
	cJSON_Delete(files);

	for(size_t i = 0; i < n_find_names; i++)
	{
		size_t size = 0;
		const char *payload = find_file_in_tar_c(tar, len, find_names[i], &size);
		const bool found = payload != NULL;
		text_find(out, find_names[i], found, found ? (size_t)(payload - (const char *)tar) : 0, size);
	}
}

// The Rust version: the list, then find for each name. Runs in a forked child.
static void render_rust(const uint8_t *tar, const size_t len, struct tar_text *out)
{
	ftl_rs_after_fork();
	ftl_rs_buf entries = ftl_rs_tar_list(tar, len);
	const size_t count = entries.len / sizeof(ftl_rs_tar_entry);
	text_str(out, "list ");
	text_num(out, count);
	text_str(out, "\n");
	for(size_t i = 0; i < count; i++)
	{
		ftl_rs_tar_entry entry;
		memcpy(&entry, entries.ptr + i * sizeof(entry), sizeof(entry));

		// The name is the NUL-terminated string in the first 100 bytes of the header
		if(entry.offset > len || len - entry.offset < CMP_NAME_LEN)
		{
			text_str(out, "  entry <outside the archive>\n");
			continue;
		}
		const uint8_t *name = tar + entry.offset;
		size_t name_len = 0;
		while(name_len < CMP_NAME_LEN && name[name_len] != '\0')
			name_len++;
		if(name_len == CMP_NAME_LEN)
			text_str(out, "  entry <no NUL in the name>\n");
		else
			text_entry(out, (const char *)name, name_len, entry.size);
	}
	ftl_rs_buf_free(&entries);

	for(size_t i = 0; i < n_find_names; i++)
	{
		size_t offset = 0;
		size_t size = 0;
		const bool found = ftl_rs_tar_find(tar, len, find_names[i], &offset, &size);
		text_find(out, find_names[i], found, offset, size);
	}
}

// Runs render(tar, len) in a forked child and reads what it prints. The child
// is killed after CHILD_TIMEOUT_S seconds. Returns false if it could not start.
static bool run_child(const tar_render_fn render, const uint8_t *tar, const size_t len, struct tar_run *run)
{
	memset(run, 0, sizeof(*run));
	int fds[2];
	if(pipe(fds) != 0)
		return false;
	// The child exits with the stdio buffers it inherited, so flush them first
	fflush(NULL);
	const pid_t pid = fork();
	if(pid < 0)
	{
		close(fds[0]);
		close(fds[1]);
		return false;
	}
	if(pid == 0)
	{
		close(fds[0]);
		dup2(fds[1], STDOUT_FILENO);
		close(fds[1]);
		signal(SIGALRM, SIG_DFL);
		alarm(CHILD_TIMEOUT_S);
		struct tar_text out = { NULL, 0, 0 };
		render(tar, len, &out);
		fwrite(out.s, 1, out.len, stdout);
		fflush(stdout);
		_exit(EXIT_SUCCESS);
	}
	close(fds[1]);

	// Read while the child writes: its output can be larger than the pipe buffer
	char chunk[4096];
	for(;;)
	{
		const ssize_t n = read(fds[0], chunk, sizeof(chunk));
		if(n < 0 && errno == EINTR)
			continue;
		if(n <= 0)
			break;
		text_add(&run->out, chunk, (size_t)n);
	}
	close(fds[0]);
	text_add(&run->out, "", 0);

	int status = 0;
	if(waitpid(pid, &status, 0) != pid)
		run->failed = true;
	else if(WIFSIGNALED(status))
	{
		run->failed = true;
		run->signaled = true;
		run->number = WTERMSIG(status);
	}
	else if(!WIFEXITED(status) || WEXITSTATUS(status) != EXIT_SUCCESS)
	{
		run->failed = true;
		run->number = WIFEXITED(status) ? WEXITSTATUS(status) : 0;
	}
	return true;
}

static void describe(const struct tar_run *run, char *buf, const size_t size)
{
	if(run->signaled)
		snprintf(buf, size, "was killed by signal %d", run->number);
	else
		snprintf(buf, size, "exited with status %d", run->number);
}

// Prints the first lines of a result, and says if there are more
static void print_head(const char *text)
{
	const char *p = text;
	for(size_t lines = 0; *p != '\0' && lines < MAX_SHOWN_LINES; lines++)
	{
		const char *end = strchr(p, '\n');
		const size_t len = end == NULL ? strlen(p) : (size_t)(end - p) + 1;
		printf("%.*s", (int)len, p);
		p += len;
	}
	if(*p != '\0')
		printf("...\n");
}

static void difference(const char *what, const char *c_text, const char *rust_text)
{
	differences++;
	if(differences > MAX_DIFFERENCES_SHOWN)
		return;
	printf("difference: %s\n--- C:\n", what);
	print_head(c_text);
	printf("--- Rust:\n");
	print_head(rust_text);
}

// Runs the C reference and the Rust version on one archive and compares them
static void compare_one(const char *what, const uint8_t *tar, const size_t len)
{
	struct tar_run c;
	struct tar_run rust;
	inputs++;
	if(!run_child(render_c, tar, len, &c) || !run_child(render_rust, tar, len, &rust))
	{
		printf("rust-compare tar: a child process could not be started\n");
		exit(EXIT_FAILURE);
	}
	if(rust.failed)
	{
		char how[64];
		char why[160];
		describe(&rust, how, sizeof(how));
		snprintf(why, sizeof(why), "the Rust version %s\n", how);
		difference(what, c.out.s, why);
	}
	else if(c.failed)
	{
		char how[64];
		describe(&c, how, sizeof(how));
		c_bugs++;
		if(c_bugs <= MAX_DIFFERENCES_SHOWN)
			printf("C bug: %s: the C reference %s (not counted as a difference)\n", what, how);
	}
	else if(strcmp(c.out.s, rust.out.s) != 0)
		difference(what, c.out.s, rust.out.s);
	text_free(&c.out);
	text_free(&rust.out);
}

static void archive_reserve(struct tar_archive *a, size_t cap)
{
	if(cap < 16)
		cap = 16;
	if(cap <= a->cap)
		return;
	uint8_t *grown = realloc(a->data, cap);
	if(grown == NULL)
	{
		printf("rust-compare tar: out of memory\n");
		exit(EXIT_FAILURE);
	}
	a->data = grown;
	a->cap = cap;
}

static void archive_append(struct tar_archive *a, const uint8_t *src, const size_t n)
{
	archive_reserve(a, a->len + n);
	if(n > 0)
		memcpy(a->data + a->len, src, n);
	a->len += n;
}

static void archive_free(struct tar_archive *a)
{
	free(a->data);
	a->len = 0;
	a->cap = 0;
}

// Adds an archive to the bases (which the archive is moved into) and compares it
static void add_and_compare(const char *what, struct tar_archive *input)
{
	if(n_bases == MAX_BASES)
	{
		printf("rust-compare tar: too many inputs\n");
		exit(EXIT_FAILURE);
	}
	struct tar_base *base = &bases[n_bases++];
	snprintf(base->what, sizeof(base->what), "%s", what);
	base->archive = *input;
	compare_one(base->what, base->archive.data, base->archive.len);
}

// Reads a whole file into the archive, if it is not larger than MAX_ARCHIVE_BYTES
static bool read_archive(const char *path, struct tar_archive *input)
{
	FILE *file = fopen(path, "rb");
	if(file == NULL)
		return false;
	bool ok = false;
	if(fseek(file, 0, SEEK_END) == 0)
	{
		const long size = ftell(file);
		if(size >= 0 && (unsigned long)size <= MAX_ARCHIVE_BYTES && fseek(file, 0, SEEK_SET) == 0)
		{
			archive_reserve(input, (size_t)size + 1);
			input->len = fread(input->data, 1, (size_t)size, file);
			ok = input->len == (size_t)size;
		}
	}
	fclose(file);
	return ok;
}

// The archives of VECTOR_DIR, in name order, compared as bases
static bool add_vectors(void)
{
	DIR *dir = opendir(VECTOR_DIR);
	if(dir == NULL)
	{
		printf("rust-compare tar: cannot read %s: %s\n", VECTOR_DIR, strerror(errno));
		return false;
	}
	static char names[MAX_VECTORS][300];
	size_t n = 0;
	for(struct dirent *entry = readdir(dir); entry != NULL && n < MAX_VECTORS; entry = readdir(dir))
	{
		const size_t len = strlen(entry->d_name);
		if(len > 4 && strcmp(entry->d_name + len - 4, ".tar") == 0)
			snprintf(names[n++], sizeof(names[0]), "%s", entry->d_name);
	}
	closedir(dir);

	// readdir() order depends on the file system, so sort the names
	for(size_t i = 1; i < n; i++)
		for(size_t j = i; j > 0 && strcmp(names[j - 1], names[j]) > 0; j--)
		{
			char swap[300];
			memcpy(swap, names[j - 1], sizeof(swap));
			memcpy(names[j - 1], names[j], sizeof(swap));
			memcpy(names[j], swap, sizeof(swap));
		}

	for(size_t i = 0; i < n; i++)
	{
		char path[600];
		snprintf(path, sizeof(path), "%s/%s", VECTOR_DIR, names[i]);
		struct tar_archive input = { NULL, 0, 0 };
		if(!read_archive(path, &input))
		{
			printf("rust-compare tar: cannot read %s\n", path);
			archive_free(&input);
			return false;
		}
		char what[1024];
		snprintf(what, sizeof(what), "vector %s", path);
		add_and_compare(what, &input);
	}
	return true;
}

// Appends one entry: a header with the name and the size, then the data (a
// pattern) padded to whole blocks. name_len may be 100: then the name field has
// no NUL.
static void add_entry(struct tar_archive *input, const char *name, const size_t name_len, const size_t size)
{
	uint8_t header[CMP_BLOCK];
	memset(header, 0, sizeof(header));
	memcpy(header, name, name_len);
	char field[32];
	snprintf(field, sizeof(field), "%011zo", size);
	memcpy(header + CMP_SIZE_OFFSET, field, CMP_SIZE_LEN - 1);
	memcpy(header + CMP_MAGIC_OFFSET, "ustar\0" "00", 8);
	archive_append(input, header, sizeof(header));

	const size_t padded = (size + CMP_BLOCK - 1) / CMP_BLOCK * CMP_BLOCK;
	archive_reserve(input, input->len + padded);
	for(size_t i = 0; i < padded; i++)
		input->data[input->len++] = i < size ? (uint8_t)('A' + i % 26) : (uint8_t)0;
}

// The generated archives: one entry of every size and name length, with and
// without the end blocks; 300 entries; 40 entries with 99 and 100 byte names
static void add_generated(void)
{
	char what[1024];
	for(size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
		for(size_t n = 0; n < sizeof(name_lens) / sizeof(name_lens[0]); n++)
			for(size_t end = 0; end < 2; end++)
			{
				const char *name = name_lens[n] == 1 ? "e" : name_lens[n] == 99 ? name99 : name100;
				struct tar_archive input = { NULL, 0, 0 };
				add_entry(&input, name, name_lens[n], sizes[s]);
				if(end == 1)
					archive_append(&input, zero_blocks, sizeof(zero_blocks));
				snprintf(what, sizeof(what), "generated: one entry of %zu bytes, a %zu byte name, %s",
				         sizes[s], name_lens[n], end == 1 ? "with end blocks" : "without end blocks");
				add_and_compare(what, &input);
			}

	for(size_t end = 0; end < 2; end++)
	{
		struct tar_archive input = { NULL, 0, 0 };
		for(size_t i = 0; i < 300; i++)
		{
			char entry_name[32];
			snprintf(entry_name, sizeof(entry_name), "entry-%03zu", i);
			add_entry(&input, entry_name, strlen(entry_name), sizes[i % (sizeof(sizes) / sizeof(sizes[0]))]);
		}
		if(end == 1)
			archive_append(&input, zero_blocks, sizeof(zero_blocks));
		snprintf(what, sizeof(what), "generated: 300 entries, %s", end == 1 ? "with end blocks" : "without end blocks");
		add_and_compare(what, &input);
	}

	for(size_t end = 0; end < 2; end++)
	{
		struct tar_archive input = { NULL, 0, 0 };
		for(size_t i = 0; i < 40; i++)
		{
			const size_t len = i % 2 == 1 ? 100 : 99;
			const char *name = len == 99 ? name99 : name100;
			add_entry(&input, name, len, i % 3 == 0 ? 0 : 513);
		}
		if(end == 1)
			archive_append(&input, zero_blocks, sizeof(zero_blocks));
		snprintf(what, sizeof(what), "generated: 40 entries with 99 and 100 byte names, %s",
		         end == 1 ? "with end blocks" : "without end blocks");
		add_and_compare(what, &input);
	}
}

static uint64_t next_random(uint64_t *state)
{
	uint64_t x = *state;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*state = x;
	return x * 0x2545F4914F6CDD1Dull;
}

static size_t random_below(uint64_t *state, const size_t n)
{
	return n == 0 ? 0 : (size_t)(next_random(state) % n);
}

// Writes a size field: a value from a list of odd ones, random bytes, or a
// random octal number (11 digits and a NUL)
static void put_size_field(uint8_t *field, uint64_t *rng)
{
	static const char *const variants[] = { "00000000000", "77777777777", "777777777777", "   ",
	                                        "0000000x000", "00000000008", "1 1", "        1", "00000000001 " };
	const size_t choice = random_below(rng, 11);
	memset(field, 0, CMP_SIZE_LEN);
	if(choice < sizeof(variants) / sizeof(variants[0]))
		memcpy(field, variants[choice], strlen(variants[choice]));
	else if(choice == 9)
	{
		for(size_t i = 0; i < CMP_SIZE_LEN; i++)
			field[i] = (uint8_t)next_random(rng);
	}
	else
	{
		char octal[32];
		snprintf(octal, sizeof(octal), "%011llo", (unsigned long long)(next_random(rng) % (1ull << 33)));
		memcpy(field, octal, CMP_SIZE_LEN - 1);
	}
}

static void insert_block(struct tar_archive *input, const size_t at, uint64_t *rng)
{
	archive_reserve(input, input->len + CMP_BLOCK);
	memmove(input->data + at + CMP_BLOCK, input->data + at, input->len - at);
	for(size_t i = 0; i < CMP_BLOCK; i++)
		input->data[at + i] = random_below(rng, 2) == 0 ? (uint8_t)next_random(rng) : (uint8_t)0;
	input->len += CMP_BLOCK;
}

static void delete_block(struct tar_archive *input, const size_t at)
{
	memmove(input->data + at, input->data + at + CMP_BLOCK, input->len - at - CMP_BLOCK);
	input->len -= CMP_BLOCK;
}

// One to three of: bit flip, random byte, truncation, a size field, a name
// byte, a magic byte, a block inserted or removed at a block boundary
static void mutate(struct tar_archive *input, uint64_t *rng)
{
	const size_t ops = 1 + random_below(rng, 3);
	for(size_t op = 0; op < ops; op++)
	{
		const size_t blocks = input->len / CMP_BLOCK;
		switch(random_below(rng, 8))
		{
		case 0:
			if(input->len > 0)
			{
				const size_t at = random_below(rng, input->len);
				input->data[at] ^= (uint8_t)(1u << random_below(rng, 8));
			}
			break;
		case 1:
			if(input->len > 0)
			{
				const size_t at = random_below(rng, input->len);
				input->data[at] = (uint8_t)next_random(rng);
			}
			break;
		case 2:
			input->len = random_below(rng, input->len + 1);
			break;
		case 3:
			if(blocks > 0)
			{
				const size_t at = random_below(rng, blocks) * CMP_BLOCK + CMP_SIZE_OFFSET;
				put_size_field(input->data + at, rng);
			}
			break;
		case 4:
			if(blocks > 0)
			{
				static const uint8_t bytes[] = { 0, 'x', 0xff };
				const size_t at = random_below(rng, blocks) * CMP_BLOCK + random_below(rng, CMP_NAME_LEN);
				input->data[at] = bytes[random_below(rng, 3)];
			}
			break;
		case 5:
			if(blocks > 0)
			{
				const size_t at = random_below(rng, blocks) * CMP_BLOCK + CMP_MAGIC_OFFSET + random_below(rng, 8);
				input->data[at] = (uint8_t)next_random(rng);
			}
			break;
		case 6:
			insert_block(input, random_below(rng, blocks + 1) * CMP_BLOCK, rng);
			break;
		default:
			if(blocks > 0)
				delete_block(input, random_below(rng, blocks) * CMP_BLOCK);
			break;
		}
	}
}

static void check_mutants(void)
{
	uint64_t rng = 0x9E3779B97F4A7C15ull;
	if(n_bases == 0)
		return;
	for(unsigned int k = 0; k < MUTANTS; k++)
	{
		const struct tar_base *base = &bases[random_below(&rng, n_bases)];
		struct tar_archive input = { NULL, 0, 0 };
		archive_append(&input, base->archive.data, base->archive.len);
		mutate(&input, &rng);
		char what[1400];
		snprintf(what, sizeof(what), "mutant %u of %s (%zu bytes)", k, base->what, input.len);
		compare_one(what, input.data, input.len);
		archive_free(&input);
	}
}

// The names that find is asked for in every archive: the names of the vectors,
// a missing name, the empty name, and names of 1, 99 and 100 bytes
static void init_names(void)
{
	memset(name99, 'n', CMP_NAME_LEN - 1);
	memset(name100, 'n', CMP_NAME_LEN);
	const char *names[] = { "entry", "e", "target", "bad-size", "first", "skip", "adlist.json", "absent",
	                        "entry-000", "entry-001", "", name99, name100 };
	for(size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		find_names[n_find_names++] = names[i];
}

static void free_bases(void)
{
	for(size_t i = 0; i < n_bases; i++)
		archive_free(&bases[i].archive);
	n_bases = 0;
}

int ftl_rs_compare_tar(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	init_names();
	if(add_vectors())
	{
		add_generated();
		check_mutants();
	}
	free_bases();

	if(differences > MAX_DIFFERENCES_SHOWN)
		printf("... %u more differences not shown\n", differences - MAX_DIFFERENCES_SHOWN);
	if(c_bugs > 0)
		printf("rust-compare tar: the C reference crashed on %u inputs (C bugs, not counted as differences)\n", c_bugs);
	printf("rust-compare tar: %u inputs, %u differences\n", inputs, differences);
	return differences == 0 && inputs > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
