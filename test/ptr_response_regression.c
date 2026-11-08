#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "config/config.h"
#include "log.h"
#include "syscalls/syscalls.h"

#define TEST_MAXDOMAINLEN 256
#define DNS_HEADER_LEN 12
#define DNS_TYPE_PTR 12
#define DNS_CLASS_IN 1
// Mirrors RESOLVER_TIMEOUT_MS in src/resolve.c. It is exported as a plain
// number because it sets how long a withheld reply takes to time out
#define FTL_RESOLVER_TIMEOUT_MS 2000

// Test cases. Each name is also the file prefix of its exported vectors
#define STALE_CASE "stale_reply_then_valid"
#define INVALID_BANG_CASE "invalid_name_bang"
#define INVALID_SPACE_CASE "invalid_name_space"
#define INVALID_EMPTY_CASE "invalid_name_empty"
#define VECTOR_OP "resolveHostname"
#define LATE_A_ADDR "192.0.2.10"
#define LATE_A_TARGET "late-a.example"
#define ANSWER_B_ADDR "192.0.2.11"
#define ANSWER_B_TARGET "answer-b.example"

bool resolveHostname(const int sock, const bool tcp,
                     char hostn[TEST_MAXDOMAINLEN], const char *addr,
                     const bool force, bool *truncated);

struct config config = { 0 };
bool debug_flags[DEBUG_MAX] = { false };
bool only_testing = true;

bool get_secure_randomness(uint8_t *buffer, const size_t length)
{
	// The production resolver obtains cryptographically secure query IDs.
	// This standalone regression harness only needs distinct, reproducible
	// IDs so stale replies can be correlated deterministically.
	static uint8_t next = 1;

	if(buffer == NULL)
		return false;

	for(size_t i = 0; i < length; i++)
		buffer[i] = next++;

	return true;
}


void _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	(void)priority;
	(void)flag;
	(void)format;
}

char *escape_string(const char *input)
{
	if(input == NULL)
		return NULL;
	const size_t len = strlen(input) + 1;
	char *copy = malloc(len);
	if(copy != NULL)
		memcpy(copy, input, len);
	return copy;
}

static unsigned int hostname_warnings = 0;
static char last_warning_name[TEST_MAXDOMAINLEN] = { 0 };
static unsigned int last_warning_pos = 0;

void log_hostname_warning(const char *ip, const char *name, const unsigned int pos)
{
	(void)ip;
	hostname_warnings++;
	snprintf(last_warning_name, sizeof(last_warning_name), "%s", name);
	last_warning_pos = pos;
}

void *FTLcalloc(size_t n, size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return calloc(n, size);
}

bool FTLfree(void *ptr, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	free(ptr);
	return true;
}

size_t FTLstrlen(const char *s, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strlen(s);
}

char *FTLstrncpy(char *dest, const char *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strncpy(dest, src, n);
}

char *FTLstrncat(char *dest, const char *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strncat(dest, src, n);
}

void *FTLmemcpy(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcpy(dest, src, n);
}

void *FTLmemset(void *s, const int c, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memset(s, c, n);
}

char *FTLstrstr(const char *haystack, const char *needle, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strstr(haystack, needle);
}

int FTLstrcmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strcmp(s1, s2);
}

int FTLstrcasecmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strcasecmp(s1, s2);
}

int FTLsnprintf(const char *file, const char *func, const int line,
                char *buffer, const size_t maxlen, const char *format, ...)
{
	(void)file;
	(void)func;
	(void)line;
	va_list args;
	va_start(args, format);
	const int result = vsnprintf(buffer, maxlen, format, args);
	va_end(args);
	return result;
}

ssize_t FTLsendto(int sockfd, void *buf, size_t len, int flags,
                  const struct sockaddr *dest_addr, socklen_t addrlen, const bool warn,
                  const char *file, const char *func, const int line)
{
	(void)warn;
	(void)file;
	(void)func;
	(void)line;
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t FTLrecvfrom(int sockfd, void *buf, size_t len, int flags,
                    struct sockaddr *src_addr, socklen_t *addrlen,
                    const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t FTLrecv(int sockfd, void *buf, size_t len, int flags, const bool warn,
                const char *file, const char *func, const int line)
{
	(void)warn;
	(void)file;
	(void)func;
	(void)line;
	return recv(sockfd, buf, len, flags);
}

struct server_context {
	int sock;
	const char *test;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool release_delayed_a;
	bool success;
};

static bool dns_question_end(const uint8_t *query, const size_t query_len, size_t *end)
{
	if(query_len < DNS_HEADER_LEN + 1)
		return false;

	size_t pos = DNS_HEADER_LEN;
	while(pos < query_len)
	{
		const uint8_t label_len = query[pos++];
		if(label_len == 0)
			break;
		if(label_len > 63 || pos + label_len > query_len)
			return false;
		pos += label_len;
	}

	if(pos + 4 > query_len)
		return false;

	*end = pos + 4;
	return true;
}

static bool encode_dns_name(uint8_t *out, const size_t out_len, const char *name, size_t *encoded_len)
{
	size_t used = 0;
	const char *label = name;
	while(*label != '\0')
	{
		const char *dot = strchr(label, '.');
		const size_t len = dot == NULL ? strlen(label) : (size_t)(dot - label);
		if(len == 0 || len > 63 || used + 1 + len >= out_len)
			return false;
		out[used++] = (uint8_t)len;
		memcpy(out + used, label, len);
		used += len;
		if(dot == NULL)
			break;
		label = dot + 1;
	}
	if(used >= out_len)
		return false;
	out[used++] = 0;
	*encoded_len = used;
	return true;
}

static bool build_ptr_response(const uint8_t *query, const size_t query_len,
                               const char *target, uint8_t *response,
                               const size_t response_size, size_t *response_len)
{
	size_t question_end = 0;
	if(!dns_question_end(query, query_len, &question_end) || question_end + 12 >= response_size)
		return false;

	memset(response, 0, response_size);
	memcpy(response, query, question_end);
	response[2] = 0x81;
	response[3] = 0x80;
	response[4] = 0x00;
	response[5] = 0x01;
	response[6] = 0x00;
	response[7] = 0x01;
	response[8] = 0x00;
	response[9] = 0x00;
	response[10] = 0x00;
	response[11] = 0x00;

	size_t pos = question_end;
	response[pos++] = 0xc0;
	response[pos++] = 0x0c;
	response[pos++] = 0x00;
	response[pos++] = DNS_TYPE_PTR;
	response[pos++] = 0x00;
	response[pos++] = DNS_CLASS_IN;
	response[pos++] = 0x00;
	response[pos++] = 0x00;
	response[pos++] = 0x00;
	response[pos++] = 0x00;

	uint8_t encoded[256] = { 0 };
	size_t encoded_len = 0;
	if(!encode_dns_name(encoded, sizeof(encoded), target, &encoded_len) ||
	   encoded_len > UINT16_MAX || pos + 2 + encoded_len > response_size)
		return false;

	response[pos++] = (uint8_t)(encoded_len >> 8);
	response[pos++] = (uint8_t)(encoded_len & 0xffu);
	memcpy(response + pos, encoded, encoded_len);
	pos += encoded_len;
	*response_len = pos;
	return true;
}

// Vector export (--export-vectors DIR). export_dir stays NULL in normal runs
// and every helper below is then skipped, so those runs are unchanged. Packets
// are written when the fake server sends or receives them. The manifest is
// written by the test code after the server threads have been joined, so its
// order follows the test sequence and not thread scheduling.
static const char *export_dir = NULL;
static FILE *manifest = NULL;
static unsigned int json_depth = 0;
static bool json_comma = false;
static unsigned int vectors_written = 0;
static bool export_failed = false;

static void vector_file_name(char *name, const size_t len, const char *test,
                             const unsigned int index, const char *role)
{
	snprintf(name, len, "%s-%02u-%s.bin", test, index, role);
}

// Writes one packet of exchange index of test. role is "query" or "response"
static void export_packet(const char *test, const unsigned int index, const char *role,
                          const uint8_t *data, const size_t len)
{
	if(export_dir == NULL)
		return;

	char name[128] = { 0 };
	char path[PATH_MAX] = { 0 };
	vector_file_name(name, sizeof(name), test, index, role);
	if(snprintf(path, sizeof(path), "%s/%s", export_dir, name) >= (int)sizeof(path))
	{
		fprintf(stderr, "Vector path too long: %s/%s\n", export_dir, name);
		export_failed = true;
		return;
	}

	FILE *fp = fopen(path, "wb");
	if(fp == NULL)
	{
		fprintf(stderr, "Cannot create %s: %s\n", path, strerror(errno));
		export_failed = true;
		return;
	}
	const bool written = fwrite(data, 1, len, fp) == len;
	if(fclose(fp) != 0 || !written)
	{
		fprintf(stderr, "Cannot write %s\n", path);
		export_failed = true;
	}
}

// Exports a reply, then sends it. Returns the sendto() result
static ssize_t send_reply(const char *test, const unsigned int index, const int sock,
                          const uint8_t *response, const size_t response_len,
                          const struct sockaddr *client, const socklen_t client_len)
{
	export_packet(test, index, "response", response, response_len);
	return sendto(sock, response, response_len, 0, client, client_len);
}

// Streaming JSON writer for the manifest. json_depth is the nesting level of
// the open container and json_comma tells whether it already has a member
static void json_newline(void)
{
	fputc('\n', manifest);
	for(unsigned int i = 0; i < json_depth; i++)
		fputs("  ", manifest);
}

// Writes s as a JSON string. Quotes, backslashes and bytes outside printable
// ASCII are escaped, so no name taken from a packet can break the file
static void json_string(const char *s)
{
	fputc('"', manifest);
	for(const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++)
	{
		if(*p == '"')
			fputs("\\\"", manifest);
		else if(*p == '\\')
			fputs("\\\\", manifest);
		else if(*p < 0x20 || *p >= 0x7f)
			fprintf(manifest, "\\u%04x", (unsigned int)*p);
		else
			fputc(*p, manifest);
	}
	fputc('"', manifest);
}

static void json_separate(void)
{
	if(json_comma)
		fputc(',', manifest);
	json_newline();
	json_comma = true;
}

static void json_key(const char *key)
{
	json_separate();
	json_string(key);
	fputs(": ", manifest);
}

static void json_str(const char *key, const char *value)
{
	json_key(key);
	json_string(value);
}

static void json_uint(const char *key, const unsigned int value)
{
	json_key(key);
	fprintf(manifest, "%u", value);
}

static void json_bool(const char *key, const bool value)
{
	json_key(key);
	fputs(value ? "true" : "false", manifest);
}

static void json_null(const char *key)
{
	json_key(key);
	fputs("null", manifest);
}

static void json_str_or_null(const char *key, const char *value)
{
	if(value != NULL)
		json_str(key, value);
	else
		json_null(key);
}

// Opens an object or array as member key, or as the next array element when
// key is NULL
static void json_open(const char *key, const char open)
{
	if(key != NULL)
		json_key(key);
	else
		json_separate();
	fputc(open, manifest);
	json_depth++;
	json_comma = false;
}

static void json_close(const char close)
{
	json_depth--;
	if(json_comma)
		json_newline();
	fputc(close, manifest);
	json_comma = true;
}

// Creates DIR and opens DIR/manifest.json. Returns false if that fails
static bool export_begin(const char *dir)
{
	if(mkdir(dir, 0777) != 0 && errno != EEXIST)
	{
		fprintf(stderr, "Cannot create %s: %s\n", dir, strerror(errno));
		return false;
	}

	char path[PATH_MAX] = { 0 };
	if(snprintf(path, sizeof(path), "%s/manifest.json", dir) >= (int)sizeof(path))
	{
		fprintf(stderr, "Vector path too long: %s\n", dir);
		return false;
	}
	manifest = fopen(path, "w");
	if(manifest == NULL)
	{
		fprintf(stderr, "Cannot create %s: %s\n", path, strerror(errno));
		return false;
	}

	export_dir = dir;
	fputc('{', manifest);
	json_depth = 1;
	json_comma = false;
	json_str("module", "ptr_response");
	json_str("generator", "test/ptr_response_regression.c");
	json_open("vectors", '[');
	return true;
}

// Starts a vector entry. Its args and expect members are written by the caller,
// then json_close('}') ends it
static void vector_begin(const char *test, const unsigned int index, const char *role)
{
	char file[128] = { 0 };
	vector_file_name(file, sizeof(file), test, index, role);
	json_open(NULL, '{');
	json_str("file", file);
	json_str("test", test);
	json_str("op", VECTOR_OP);
	vectors_written++;
}

// One query entry. outcome is "name" (name returned), "timeout" (no reply
// within the resolver timeout) or "no_name" (a reply came, but gave no name)
static void manifest_query(const char *test, const unsigned int index, const char *lookup_addr,
                           const char *outcome, const char *name,
                           const char *warn_name, const unsigned int warn_pos)
{
	char answered_by[128] = { 0 };
	vector_file_name(answered_by, sizeof(answered_by), test, index, "response");

	vector_begin(test, index, "query");
	json_open("args", '{');
	json_str("packet", "query");
	json_uint("exchange", index);
	json_str("lookup_addr", lookup_addr);
	json_uint("qtype", DNS_TYPE_PTR);
	json_uint("qclass", DNS_CLASS_IN);
	json_bool("tcp", false);
	json_bool("force", true);
	json_uint("resolver_timeout_ms", FTL_RESOLVER_TIMEOUT_MS);
	json_str("answered_by", answered_by);
	json_close('}');

	json_open("expect", '{');
	json_str("outcome", outcome);
	json_str_or_null("name", name);
	if(warn_name != NULL)
	{
		json_open("hostname_warning", '{');
		json_str("name", warn_name);
		json_uint("pos", warn_pos);
		json_close('}');
	}
	else
		json_null("hostname_warning");
	json_close('}');
	json_close('}');
}

// One reply entry. name is the host name FTL took from this packet, or NULL
// if it was rejected, and reason says why it was rejected
static void manifest_response(const char *test, const unsigned int index, const char *target,
                              const char *lookup_addr, const unsigned int delay_ms,
                              const char *name, const char *reason)
{
	char answers[128] = { 0 };
	vector_file_name(answers, sizeof(answers), test, index, "query");

	vector_begin(test, index, "response");
	json_open("args", '{');
	json_str("packet", "response");
	json_uint("exchange", index);
	json_str("answers_query", answers);
	json_str("ptr_target", target);
	json_str("delivered_during_lookup", lookup_addr);
	json_uint("delay_ms", delay_ms);
	json_close('}');

	json_open("expect", '{');
	json_bool("accepted", name != NULL);
	json_str_or_null("name", name);
	json_str_or_null("reason", reason);
	json_close('}');
	json_close('}');
}

// The reply to lookup 1 is held until that lookup has timed out. It is then
// delivered during lookup 2, which must discard it and accept its own answer
static void manifest_stale_case(const bool second_ok, const char *host_b)
{
	const bool late_taken = strcmp(host_b, LATE_A_TARGET) == 0;
	const bool answer_taken = second_ok && strcmp(host_b, ANSWER_B_TARGET) == 0;

	manifest_query(STALE_CASE, 1, LATE_A_ADDR, "timeout", NULL, NULL, 0);
	manifest_response(STALE_CASE, 1, LATE_A_TARGET, ANSWER_B_ADDR, FTL_RESOLVER_TIMEOUT_MS,
	                  late_taken ? LATE_A_TARGET : NULL,
	                  late_taken ? NULL : "reply to an earlier query, id does not match");
	manifest_query(STALE_CASE, 2, ANSWER_B_ADDR, second_ok ? "name" : "no_name",
	               second_ok ? host_b : NULL, NULL, 0);
	manifest_response(STALE_CASE, 2, ANSWER_B_TARGET, ANSWER_B_ADDR, 0,
	                  answer_taken ? ANSWER_B_TARGET : NULL,
	                  answer_taken ? NULL : "answer does not match the expected name");
}

// A single reply carrying an invalid host name, or an empty one
static void manifest_invalid_case(const char *test, const char *lookup_addr, const char *target,
                                  const char *name, const char *warn_name,
                                  const unsigned int warn_pos)
{
	manifest_query(test, 1, lookup_addr, name != NULL ? "name" : "no_name", name,
	               warn_name, warn_pos);
	manifest_response(test, 1, target, lookup_addr, 0, NULL,
	                  target[0] == '\0' ? "empty name, no invalid character to report"
	                                    : "answer name has an invalid character");
}

// Closes the manifest. Returns false if any vector or the manifest failed to be
// written, so that a partial export cannot pass
static bool export_end(void)
{
	if(export_dir == NULL)
		return true;

	json_close(']');
	json_close('}');
	fputc('\n', manifest);
	if(ferror(manifest) || fclose(manifest) != 0)
		export_failed = true;
	manifest = NULL;
	printf("VECTORS_EXPORTED=%u\n", vectors_written);
	return !export_failed;
}

static void *server_main(void *arg)
{
	struct server_context *ctx = arg;
	uint8_t query_a[512] = { 0 };
	uint8_t query_b[512] = { 0 };
	uint8_t response[512] = { 0 };
	struct sockaddr_in client = { 0 };
	socklen_t client_len = sizeof(client);

	const ssize_t a_len = recvfrom(ctx->sock, query_a, sizeof(query_a), 0,
	                               (struct sockaddr *)&client, &client_len);
	if(a_len <= 0)
		return NULL;
	export_packet(ctx->test, 1, "query", query_a, (size_t)a_len);

	pthread_mutex_lock(&ctx->mutex);
	while(!ctx->release_delayed_a)
		pthread_cond_wait(&ctx->condition, &ctx->mutex);
	pthread_mutex_unlock(&ctx->mutex);

	size_t response_len = 0;
	if(!build_ptr_response(query_a, (size_t)a_len, LATE_A_TARGET,
	                       response, sizeof(response), &response_len))
		return NULL;
	if(send_reply(ctx->test, 1, ctx->sock, response, response_len,
	              (const struct sockaddr *)&client, client_len) != (ssize_t)response_len)
		return NULL;

	client_len = sizeof(client);
	const ssize_t b_len = recvfrom(ctx->sock, query_b, sizeof(query_b), 0,
	                               (struct sockaddr *)&client, &client_len);
	if(b_len <= 0)
		return NULL;
	export_packet(ctx->test, 2, "query", query_b, (size_t)b_len);

	if(!build_ptr_response(query_b, (size_t)b_len, ANSWER_B_TARGET,
	                       response, sizeof(response), &response_len))
		return NULL;
	if(send_reply(ctx->test, 2, ctx->sock, response, response_len,
	              (const struct sockaddr *)&client, client_len) != (ssize_t)response_len)
		return NULL;

	ctx->success = true;
	return NULL;
}

struct single_answer_context {
	int sock;
	const char *test;
	const char *target;
};

static void *serve_single_answer(void *arg)
{
	const struct single_answer_context *ctx = arg;
	uint8_t query[512] = { 0 };
	uint8_t response[512] = { 0 };
	struct sockaddr_in client = { 0 };
	socklen_t client_len = sizeof(client);

	const ssize_t len = recvfrom(ctx->sock, query, sizeof(query), 0,
	                             (struct sockaddr *)&client, &client_len);
	if(len <= 0)
		return NULL;
	export_packet(ctx->test, 1, "query", query, (size_t)len);

	size_t response_len = 0;
	if(build_ptr_response(query, (size_t)len, ctx->target,
	                      response, sizeof(response), &response_len))
		send_reply(ctx->test, 1, ctx->sock, response, response_len,
		           (const struct sockaddr *)&client, client_len);

	return NULL;
}

// Resolve addr against a single PTR answer and check the HOSTNAME warning:
// expect_pos < 0 means no warning is expected
static bool check_invalid_answer(const char *test, const int client_sock, const int server_sock,
                                 const char *addr, const char *target,
                                 const int expect_pos)
{
	struct single_answer_context ctx = { .sock = server_sock, .test = test, .target = target };
	pthread_t thread;
	if(pthread_create(&thread, NULL, serve_single_answer, &ctx) != 0)
		return false;

	const unsigned int warnings_before = hostname_warnings;
	char host[TEST_MAXDOMAINLEN] = { 0 };
	bool truncated = false;
	const bool resolved = resolveHostname(client_sock, false, host, addr, true, &truncated);
	pthread_join(thread, NULL);

	const bool warned = hostname_warnings == warnings_before + 1;
	printf("INVALID_ANSWER \"%s\": name=\"%s\" warned=%s pos=%u\n", target,
	       warned ? last_warning_name : "", warned ? "yes" : "no",
	       warned ? last_warning_pos : 0);

	if(export_dir != NULL)
		manifest_invalid_case(test, addr, target, resolved ? host : NULL,
		                      warned ? last_warning_name : NULL,
		                      warned ? last_warning_pos : 0);

	if(expect_pos < 0)
		return hostname_warnings == warnings_before && host[0] == '\0';

	return warned && host[0] == '\0' &&
	       strcmp(last_warning_name, target) == 0 &&
	       last_warning_pos == (unsigned int)expect_pos;
}

int main(int argc, char *argv[])
{
	// Without arguments the harness only runs its checks. --export-vectors DIR
	// also writes the packets and their observed results as data files
	const char *export_arg = NULL;
	for(int i = 1; i < argc; i++)
	{
		if(strcmp(argv[i], "--export-vectors") != 0 || i + 1 >= argc || export_arg != NULL)
		{
			fprintf(stderr, "Usage: %s [--export-vectors DIR]\n", argv[0]);
			return EXIT_FAILURE;
		}
		export_arg = argv[++i];
	}
	if(export_arg != NULL && !export_begin(export_arg))
		return EXIT_FAILURE;

	int server_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(server_sock < 0)
	{
		perror("server socket");
		return EXIT_FAILURE;
	}

	struct sockaddr_in server = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port = 0,
	};
	if(bind(server_sock, (const struct sockaddr *)&server, sizeof(server)) != 0)
	{
		perror("server bind");
		close(server_sock);
		return EXIT_FAILURE;
	}

	socklen_t server_len = sizeof(server);
	if(getsockname(server_sock, (struct sockaddr *)&server, &server_len) != 0)
	{
		perror("getsockname");
		close(server_sock);
		return EXIT_FAILURE;
	}

	int client_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(client_sock < 0)
	{
		perror("client socket");
		close(server_sock);
		return EXIT_FAILURE;
	}

	const struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
	if(setsockopt(client_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
	{
		perror("setsockopt");
		close(client_sock);
		close(server_sock);
		return EXIT_FAILURE;
	}

	// FTL connects its resolver sockets, see create_socket(). That is what
	// makes the kernel filter foreign sources and deliver ICMP errors, so
	// the harness has to do the same to exercise the code path FTL uses.
	//
	// Note this one socket is deliberately reused for both lookups below,
	// which the resolver itself no longer does - it creates one per lookup.
	// Reuse is what puts the delayed reply to the first query in the way of
	// the second, so it is the shape this test needs. Do not "align" it with
	// production: a fresh source port per lookup would have the kernel drop
	// the stale reply and the correlation under test would never be reached
	if(connect(client_sock, (const struct sockaddr *)&server, sizeof(server)) != 0)
	{
		perror("client connect");
		close(client_sock);
		close(server_sock);
		return EXIT_FAILURE;
	}

	config.dns.port.v.u16 = ntohs(server.sin_port);
	struct server_context ctx = {
		.sock = server_sock,
		.test = STALE_CASE,
		.mutex = PTHREAD_MUTEX_INITIALIZER,
		.condition = PTHREAD_COND_INITIALIZER,
		.release_delayed_a = false,
		.success = false,
	};
	pthread_t thread;
	if(pthread_create(&thread, NULL, server_main, &ctx) != 0)
	{
		perror("pthread_create");
		close(client_sock);
		close(server_sock);
		return EXIT_FAILURE;
	}

	char host_a[TEST_MAXDOMAINLEN] = { 0 };
	char host_b[TEST_MAXDOMAINLEN] = { 0 };
	bool truncated = false;
	const bool first_ok = resolveHostname(client_sock, false, host_a,
	                                      LATE_A_ADDR, true, &truncated);
	pthread_mutex_lock(&ctx.mutex);
	ctx.release_delayed_a = true;
	pthread_cond_signal(&ctx.condition);
	pthread_mutex_unlock(&ctx.mutex);
	const bool second_ok = resolveHostname(client_sock, false, host_b,
	                                       ANSWER_B_ADDR, true, &truncated);

	pthread_join(thread, NULL);
	pthread_cond_destroy(&ctx.condition);
	pthread_mutex_destroy(&ctx.mutex);

	if(export_dir != NULL)
		manifest_stale_case(second_ok, host_b);

	// The HOSTNAME warning has to name the offset of the invalid character,
	// an empty answer has no invalid character to report
	bool invalid_ok = true;
	if(!check_invalid_answer(INVALID_BANG_CASE, client_sock, server_sock, "192.0.2.12", "abc!def.example", 3))
		invalid_ok = false;
	if(!check_invalid_answer(INVALID_SPACE_CASE, client_sock, server_sock, "192.0.2.13", "my host.example", 2))
		invalid_ok = false;
	if(!check_invalid_answer(INVALID_EMPTY_CASE, client_sock, server_sock, "192.0.2.14", "", -1))
		invalid_ok = false;
	printf("HOSTNAME_WARNING_POSITION=%s\n", invalid_ok ? "PASS" : "FAIL");

	close(client_sock);
	close(server_sock);

	printf("FIRST_LOOKUP_TIMEOUT=%s\n", !first_ok ? "PASS" : "FAIL");
	printf("SECOND_LOOKUP_RESULT=%s\n", second_ok ? host_b : "<failed>");
	printf("SERVER_SEQUENCE=%s\n", ctx.success ? "PASS" : "FAIL");

	const bool exported = export_end();
	if(first_ok || !second_ok || !ctx.success || strcmp(host_b, ANSWER_B_TARGET) != 0 || !invalid_ok)
	{
		printf("PTR_RESPONSE_REGRESSION=FAIL\n");
		return EXIT_FAILURE;
	}

	printf("PTR_RESPONSE_REGRESSION=PASS\n");
	if(!exported)
	{
		fprintf(stderr, "Vector export to %s failed\n", export_arg);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
