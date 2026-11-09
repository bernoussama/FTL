/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare complete: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

// Runs the C and the Rust --complete on the same command lines. Each run is a
// forked child, so every config read starts from a fresh process. The words come
// from the C output (root commands, options of each subcommand, config keys and
// their values), and the command lines are every prefix of those words, the
// non-matching words and a seeded pseudo-random set.

#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "args.h"
#include "ftl_rs.h"

#define MAX_WORDS       10          // "pihole-FTL --complete" and up to 8 words
#define MAX_LIST        1024        // words in one list
#define ARENA_SIZE      (2u << 20)  // bytes for the words of the input set
#define MAX_REPORTED    50          // lines of difference reports
#define RANDOM_CASES    1500        // pseudo-random command lines
#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))

static const char *const PROGRAMS[] = { "pihole-FTL", "/usr/bin/pihole-FTL", "pihole" };
static const char *const NON_MATCHING[] = { "zzz", "Z", "--x", "VERSION", "a b", "~" };
static const char *const SUBCOMMANDS[] = { "gravity", "ntp", "sqlite3", "arp-scan", "idn2" };
static const char *const SECOND_WORDS[] = { "", "-h", "-ni", "-x", "-" };

// A list of words. The strings are kept in the arena of struct compare.
struct list {
	const char *items[MAX_LIST];
	size_t n;
};

struct compare {
	char arena[ARENA_SIZE];
	size_t arena_used;
	size_t inputs;          // command lines compared
	size_t differences;
	size_t reported_lines;
	bool truncated;         // some differences were not printed
	bool failed;            // a child process could not be started
};

// What one run printed and how it exited
struct run {
	char *out;
	size_t len;
	int status;             // -1 if the child did not exit normally
};

// Stops the comparison because the input set does not fit
static void fatal(const char *what)
{
	printf("rust-compare complete: %s\n", what);
	exit(EXIT_FAILURE);
}

// Copies len bytes of s to the arena and returns the copy
static char *own(struct compare *cmp, const char *s, const size_t len)
{
	if(len + 1 > sizeof(cmp->arena) - cmp->arena_used)
		fatal("the word arena is full");
	char *copy = cmp->arena + cmp->arena_used;
	memcpy(copy, s, len);
	copy[len] = '\0';
	cmp->arena_used += len + 1;
	return copy;
}

// A copy of the first len bytes of s, with the letters in one case
static char *own_case(struct compare *cmp, const char *s, const size_t len, const bool upper)
{
	char *copy = own(cmp, s, len);
	for(size_t i = 0; i < len; i++)
		copy[i] = (char)(upper ? toupper((unsigned char)copy[i]) : tolower((unsigned char)copy[i]));
	return copy;
}

static void list_add(struct list *list, const char *s)
{
	if(list->n == MAX_LIST)
		fatal("a list of words is full");
	list->items[list->n++] = s;
}

static void list_add_unique(struct list *list, const char *s)
{
	for(size_t i = 0; i < list->n; i++)
		if(strcmp(list->items[i], s) == 0)
			return;
	list_add(list, s);
}

// Prints len bytes as a quoted string, with control characters escaped
static void print_escaped(const char *s, const size_t len)
{
	putchar('"');
	for(size_t i = 0; i < len; i++)
	{
		const unsigned char ch = (unsigned char)s[i];
		if(ch == '\n')
			printf("\\n");
		else if(ch == '"' || ch == '\\')
			printf("\\%c", ch);
		else if(isprint(ch))
			putchar(ch);
		else
			printf("\\x%02x", ch);
	}
	putchar('"');
}

// Runs fn(argc, argv) in a forked child with its stdout in a pipe, and reads
// what it prints. fn exits, as suggest_complete() does. Returns false if the
// child or the pipe could not be started.
static bool run_in_child(void (*fn)(const int argc, char *argv[]), const int argc, char *argv[], struct run *run)
{
	run->out = NULL;
	run->len = 0;
	run->status = -1;

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
		fn(argc, argv);
		exit(EXIT_FAILURE);
	}
	close(fds[1]);

	// Read while the child writes: its output can be larger than the pipe buffer
	bool ok = true;
	size_t cap = 0;
	for(;;)
	{
		if(run->len == cap)
		{
			const size_t grown = cap == 0 ? 256 : 2 * cap;
			char *buf = realloc(run->out, grown);
			if(buf == NULL)
			{
				ok = false;
				break;
			}
			run->out = buf;
			cap = grown;
		}
		const ssize_t n = read(fds[0], run->out + run->len, cap - run->len);
		if(n < 0 && errno == EINTR)
			continue;
		if(n <= 0)
			break;
		run->len += (size_t)n;
	}
	close(fds[0]);

	int status = 0;
	if(waitpid(pid, &status, 0) == pid && WIFEXITED(status))
		run->status = WEXITSTATUS(status);
	return ok;
}

// Sets argv to "pihole-FTL --complete" followed by rest, and returns its count
static int command_line(char *argv[MAX_WORDS], const char *const *rest, const int nrest)
{
	argv[0] = (char *)"pihole-FTL";
	argv[1] = (char *)"--complete";
	for(int i = 0; i < nrest; i++)
		argv[2 + i] = (char *)rest[i];
	return 2 + nrest;
}

// Prints one difference, while the report has room
static void report(struct compare *cmp, char *const *argv, const int argc, const struct run *c, const struct run *rust)
{
	if(cmp->reported_lines >= MAX_REPORTED)
	{
		cmp->truncated = true;
		return;
	}
	printf("difference:");
	for(int i = 0; i < argc; i++)
		printf(" '%s'", argv[i]);
	printf("\n  C    (exit %d): ", c->status);
	print_escaped(c->out, c->len);
	printf("\n  Rust (exit %d): ", rust->status);
	print_escaped(rust->out, rust->len);
	printf("\n");
	cmp->reported_lines += 3;
}

// Runs both implementations on the command line and compares them
static void check(struct compare *cmp, const char *const *rest, const int nrest)
{
	char *argv[MAX_WORDS];
	const int argc = command_line(argv, rest, nrest);
	struct run c = { 0 };
	struct run rust = { 0 };
	if(!run_in_child(suggest_complete_c, argc, argv, &c) || !run_in_child(suggest_complete, argc, argv, &rust))
		cmp->failed = true;
	else
	{
		cmp->inputs++;
		const bool same = c.status == rust.status && c.len == rust.len &&
		                  (c.len == 0 || memcmp(c.out, rust.out, c.len) == 0);
		if(!same)
		{
			cmp->differences++;
			report(cmp, argv, argc, &c, &rust);
		}
	}
	free(c.out);
	free(rust.out);
}

// Adds the lines that the C implementation prints for the command line to list
static void gather(struct compare *cmp, struct list *list, const char *const *rest, const int nrest)
{
	char *argv[MAX_WORDS];
	const int argc = command_line(argv, rest, nrest);
	struct run c = { 0 };
	if(!run_in_child(suggest_complete_c, argc, argv, &c))
	{
		cmp->failed = true;
		return;
	}
	size_t start = 0;
	for(size_t i = 0; i <= c.len; i++)
		if(i == c.len || c.out[i] == '\n')
		{
			if(i > start)
				list_add(list, own(cmp, c.out + start, i - start));
			start = i + 1;
		}
	free(c.out);
}

// Every root command with every prefix of it, and the non-matching words
static void check_roots(struct compare *cmp, const struct list *roots)
{
	for(size_t i = 0; i < roots->n; i++)
		for(size_t len = 0; len <= strlen(roots->items[i]); len++)
			for(size_t p = 0; p < ARRAY_SIZE(PROGRAMS); p++)
			{
				const char *rest[] = { PROGRAMS[p], own(cmp, roots->items[i], len) };
				check(cmp, rest, 2);
			}

	for(size_t p = 0; p < ARRAY_SIZE(PROGRAMS); p++)
	{
		const char *no_word[] = { PROGRAMS[p] };
		check(cmp, no_word, 1);
		for(size_t i = 0; i < ARRAY_SIZE(NON_MATCHING); i++)
		{
			const char *rest[] = { PROGRAMS[p], NON_MATCHING[i] };
			check(cmp, rest, 2);
		}
	}
}

// Every subcommand with every prefix of its options, and the options after a
// second word (sqlite3 drops an option that is already on the line)
static void check_subcommands(struct compare *cmp)
{
	static struct list options;
	for(size_t s = 0; s < ARRAY_SIZE(SUBCOMMANDS); s++)
	{
		const char *const sub = SUBCOMMANDS[s];
		options.n = 0;
		const char *const ask[] = { "pihole-FTL", sub, "" };
		gather(cmp, &options, ask, 3);

		for(size_t i = 0; i < options.n; i++)
			for(size_t len = 0; len <= strlen(options.items[i]); len++)
			{
				const char *rest[] = { "pihole-FTL", sub, own(cmp, options.items[i], len) };
				check(cmp, rest, 3);
			}
		for(size_t i = 0; i < ARRAY_SIZE(NON_MATCHING); i++)
		{
			const char *rest[] = { "pihole-FTL", sub, NON_MATCHING[i] };
			check(cmp, rest, 3);
		}

		const size_t n_second = ARRAY_SIZE(SECOND_WORDS) + options.n;
		for(size_t k = 0; k < n_second; k++)
		{
			const char *second = k < ARRAY_SIZE(SECOND_WORDS) ? SECOND_WORDS[k] : options.items[k - ARRAY_SIZE(SECOND_WORDS)];
			for(size_t i = 0; i < options.n; i++)
				for(size_t len = 0; len <= strlen(options.items[i]); len++)
				{
					const char *rest[] = { "pihole-FTL", sub, second, own(cmp, options.items[i], len) };
					check(cmp, rest, 4);
				}
		}
	}
}

// Every config key with every prefix of it, and the non-matching words
static void check_config_keys(struct compare *cmp, const struct list *keys)
{
	for(size_t k = 0; k < keys->n; k++)
		for(size_t len = 0; len <= strlen(keys->items[k]); len++)
		{
			const char *rest[] = { "pihole-FTL", "--config", own(cmp, keys->items[k], len) };
			check(cmp, rest, 3);
		}
	for(size_t i = 0; i < ARRAY_SIZE(NON_MATCHING); i++)
	{
		const char *rest[] = { "pihole-FTL", "--config", NON_MATCHING[i] };
		check(cmp, rest, 3);
	}
}

// For every config key: the empty word, the non-matching words, and the first
// one and two characters of each suggested value (upper and lower case, for the
// bool and enum items), the full value, and one more word after the value word
static void check_config_values(struct compare *cmp, const struct list *keys)
{
	static struct list values;
	static struct list words;
	for(size_t k = 0; k < keys->n; k++)
	{
		const char *const key = keys->items[k];
		values.n = 0;
		const char *const ask[] = { "pihole-FTL", "--config", key, "" };
		gather(cmp, &values, ask, 4);

		words.n = 0;
		list_add_unique(&words, "");
		list_add_unique(&words, own(cmp, "zz", 2));
		list_add_unique(&words, own(cmp, "Z", 1));
		for(size_t v = 0; v < values.n; v++)
		{
			const char *const value = values.items[v];
			const size_t n = strlen(value);
			for(size_t len = 1; len <= 2 && len <= n; len++)
			{
				list_add_unique(&words, own(cmp, value, len));
				list_add_unique(&words, own_case(cmp, value, len, false));
				list_add_unique(&words, own_case(cmp, value, len, true));
			}
			list_add_unique(&words, own(cmp, value, n));
		}

		for(size_t w = 0; w < words.n; w++)
		{
			const char *rest[] = { "pihole-FTL", "--config", key, words.items[w] };
			check(cmp, rest, 4);
		}
		const char *extra[] = { "pihole-FTL", "--config", key, "", "x" };
		check(cmp, extra, 5);
	}
}

// A 64-bit linear congruential generator, so the random set is the same on
// every run
static uint64_t next_random(uint64_t *state)
{
	*state = *state * 6364136223846793005u + 1442695040888963407u;
	return *state >> 33;
}

// Command lines of random words from the vocabulary. Three in four name the
// program pihole-FTL.
static void check_random(struct compare *cmp, const struct list *vocab)
{
	uint64_t state = 0x9e3779b97f4a7c15u;
	for(size_t i = 0; i < RANDOM_CASES; i++)
	{
		const char *rest[MAX_WORDS - 2];
		int nrest = 0;
		const uint64_t program = next_random(&state);
		rest[nrest++] = PROGRAMS[program % 4 == 0 ? program / 4 % ARRAY_SIZE(PROGRAMS) : 0];
		const size_t words = 1 + next_random(&state) % 5;
		for(size_t w = 0; w < words; w++)
			rest[nrest++] = vocab->items[next_random(&state) % vocab->n];
		check(cmp, rest, nrest);
	}
}

int ftl_rs_compare_complete(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	static struct compare cmp;
	static struct list roots;
	static struct list keys;
	static struct list vocab;

	gather(&cmp, &roots, (const char *const[]){ "pihole-FTL", "" }, 2);
	gather(&cmp, &keys, (const char *const[]){ "pihole-FTL", "--config", "" }, 3);
	if(cmp.failed || roots.n == 0 || keys.n == 0)
	{
		printf("rust-compare complete: could not read the words of the C implementation\n");
		return EXIT_FAILURE;
	}

	// The words that the random command lines are made of
	for(size_t i = 0; i < roots.n; i++)
		list_add(&vocab, roots.items[i]);
	for(size_t i = 0; i < ARRAY_SIZE(SUBCOMMANDS); i++)
		list_add(&vocab, SUBCOMMANDS[i]);
	for(size_t i = 0; i < keys.n; i++)
		list_add(&vocab, keys.items[i]);
	for(size_t i = 0; i < ARRAY_SIZE(SECOND_WORDS); i++)
		list_add(&vocab, SECOND_WORDS[i]);
	for(size_t i = 0; i < ARRAY_SIZE(NON_MATCHING); i++)
		list_add(&vocab, NON_MATCHING[i]);
	list_add(&vocab, "--config");
	list_add(&vocab, "true");
	list_add(&vocab, "T");
	list_add(&vocab, "IP");

	check_roots(&cmp, &roots);
	check_subcommands(&cmp);
	check_config_keys(&cmp, &keys);
	check_config_values(&cmp, &keys);
	check_random(&cmp, &vocab);

	if(cmp.truncated)
		printf("(only the first %d report lines are shown)\n", MAX_REPORTED);
	printf("rust-compare complete: %zu inputs, %zu differences\n", cmp.inputs, cmp.differences);
	if(cmp.failed)
	{
		printf("rust-compare complete: a child process could not be started\n");
		return EXIT_FAILURE;
	}
	return cmp.differences == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
