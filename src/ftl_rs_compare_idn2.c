/* Pi-hole: A black hole for Internet advertisements
*  (c) 2026 Pi-hole, LLC (https://pi-hole.net)
*  Network-wide ad blocking via your own hardware.
*
*  FTL Engine
*  pihole-FTL rust-compare idn2: C vs Rust comparison
*
*  This file is copyright under the latest version of the EUPL.
*  Please see LICENSE file for your rights under this license. */

#include <idn2.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ftl_rs.h"

// Differences after this many are counted but not printed
#define MAX_DIFFERENCES_SHOWN 50

// The inputs. Both implementations convert each of them:
// - a<cp>b.com and <cp>.com for every scalar value cp from U+0080 to U+10FFFF
//   (surrogates left out), to_ascii. Each <cp>.com that the C reference
//   converts is then decoded again from the C output (decode round trip)
// - the golden cases of test/golden/cases/idn2.cases, tricky inputs, and long
//   inputs built at run time
// - the error messages of the codes -400 to 0
enum direction { TO_ASCII, TO_UNICODE };
enum category { CAT_MIDDLE, CAT_TLD, CAT_ROUND_TRIP, CAT_GOLDEN, CAT_MESSAGE, CAT_COUNT };
static const char *const category_names[CAT_COUNT] = {
	"a<cp>b.com", "<cp>.com", "decode round trip", "golden and tricky", "error messages"
};

static unsigned int inputs[CAT_COUNT];
static unsigned int category_differences[CAT_COUNT];
static unsigned int differences = 0;

struct golden {
	const char *name;
	enum direction dir;
	const char *input;
};

static const struct golden golden_cases[] = {
	// test/golden/cases/idn2.cases
	{ "encode umlaut", TO_ASCII, "äste.com" },
	{ "decode umlaut", TO_UNICODE, "xn--ste-pla.com" },
	{ "encode sharp s", TO_ASCII, "ß.de" },
	{ "decode sharp s", TO_UNICODE, "xn--zca.de" },
	{ "encode ascii case", TO_ASCII, "Example.COM" },
	{ "encode unicode case", TO_ASCII, "ÄSTE.com" },
	{ "encode multi label", TO_ASCII, "bücher.münchen.de" },
	{ "encode emoji", TO_ASCII, "\U0001F600.com" },
	{ "decode invalid", TO_UNICODE, "xn--zz.de" },
	{ "decode ascii", TO_UNICODE, "example.com" },
	// Tricky inputs: IDNA2008 and TR46 rules, punycode and label limits
	{ "encode xn-- emoji", TO_ASCII, "xn--e28h.com" },
	{ "encode double hyphen", TO_ASCII, "ab--c.com" },
	{ "encode leading hyphen", TO_ASCII, "-ab.com" },
	{ "encode trailing hyphen", TO_ASCII, "ab-.com" },
	{ "encode ZWNJ without virama", TO_ASCII, "a\u200cb.com" },
	{ "encode ZWJ without virama", TO_ASCII, "a\u200db.com" },
	{ "encode ZWJ after virama", TO_ASCII, "\u0915\u094d\u200d\u0937.com" },
	{ "encode Hebrew and Latin", TO_ASCII, "a\u05d0.com" },
	{ "encode Arabic letter and digit", TO_ASCII, "\u0627\u0661.com" },
	{ "encode CONTEXTO middle dot", TO_ASCII, "a\u00b7b.com" },
	{ "encode CONTEXTO Arabic digits", TO_ASCII, "\u0660\u0661.com" },
	{ "encode soft hyphen", TO_ASCII, "a\u00adb.com" },
	{ "encode leading combining mark", TO_ASCII, "\u0301a.com" },
	{ "encode decomposed a tilde", TO_ASCII, "a\u0303.com" },
	{ "encode capital sharp s", TO_ASCII, "\u1e9e.de" },
	{ "encode uppercase umlaut", TO_ASCII, "B\u00dcCHER.de" },
	{ "encode final sigma", TO_ASCII, "\u03c2.com" },
	{ "encode fullwidth", TO_ASCII, "\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com" },
	{ "encode ligature", TO_ASCII, "\ufb01.com" },
	{ "encode ideographic full stop", TO_ASCII, "ab\u3002com" },
	{ "encode replacement character", TO_ASCII, "a\ufffd.com" },
	{ "encode unassigned tag character", TO_ASCII, "a\U000e0080.com" },
	{ "encode underscores", TO_ASCII, "_sip._tcp.example.com" },
	{ "encode trailing dot", TO_ASCII, "example.com." },
	{ "encode empty label", TO_ASCII, "a..b.com" },
	{ "encode single dot", TO_ASCII, "." },
	{ "encode empty", TO_ASCII, "" },
	{ "encode xn-- alone", TO_ASCII, "xn--" },
	{ "encode bad punycode", TO_ASCII, "xn--zz.de" },
	{ "decode upper case", TO_UNICODE, "XN--BCHER-KVA.DE" },
	{ "decode bucher", TO_UNICODE, "xn--bcher-kva.de" },
	{ "decode trailing dot", TO_UNICODE, "xn--bcher-kva.de." },
	{ "decode unicode input", TO_UNICODE, "bücher.de" },
	{ "decode mixed labels", TO_UNICODE, "xn--bcher-kva.xn--zca.de" },
	{ "decode emoji", TO_UNICODE, "xn--e28h.com" },
	{ "decode trailing delimiter", TO_UNICODE, "xn--ab-.com" },
	{ "decode empty punycode", TO_UNICODE, "xn--" },
	{ "decode empty label", TO_UNICODE, "a..xn--zca.de" },
	{ "decode empty", TO_UNICODE, "" },
	{ "decode single dot", TO_UNICODE, "." },
};

// Writes the UTF-8 of the scalar value cp to out, NUL-terminated, and returns
// its length
static size_t utf8_encode(uint32_t cp, char out[5])
{
	const size_t len = cp < 0x80u ? 1 : cp < 0x800u ? 2 : cp < 0x10000u ? 3 : 4;
	static const unsigned char lead[5] = { 0, 0x00, 0xC0, 0xE0, 0xF0 };
	for(size_t i = len - 1; i > 0; i--)
	{
		out[i] = (char)(0x80u | (cp & 0x3Fu));
		cp >>= 6;
	}
	out[0] = (char)(len == 1 ? cp : (cp | lead[len]));
	out[len] = '\0';
	return len;
}

// Names the input of a difference. name is set for the golden cases, otherwise
// the code point cp says which generated input it is
static void describe(char *what, const size_t size, const enum category cat,
                     const char *input, const char *name, const uint32_t cp)
{
	if(name != NULL)
		snprintf(what, size, "%s \"%s\"", name, input);
	else if(cat == CAT_MIDDLE)
		snprintf(what, size, "a U+%04X b.com", (unsigned int)cp);
	else if(cat == CAT_TLD)
		snprintf(what, size, "U+%04X.com", (unsigned int)cp);
	else
		snprintf(what, size, "decode \"%s\" (C output of U+%04X.com)", input, (unsigned int)cp);
}

// A result as text: the output in quotes, or the error code and its message
static void format_result(char *line, const size_t size, const int rc, const char *text, const bool rust)
{
	if(rc == IDN2_OK)
		snprintf(line, size, "\"%s\"", text != NULL ? text : "(no output)");
	else
		snprintf(line, size, "error %d: %s", rc, rust ? ftl_rs_idn2_strerror(rc) : idn2_strerror(rc));
}

// Counts a difference and prints it while the cap allows
static void difference(const enum category cat, const char *what, const char *c_line, const char *rust_line)
{
	category_differences[cat]++;
	differences++;
	if(differences <= MAX_DIFFERENCES_SHOWN)
		printf("difference: %s\n  C:    %s\n  Rust: %s\n", what, c_line, rust_line);
}

// Converts input with the C reference (idn2_to_ascii_8z() with the flags the
// callers use, or idn2_to_unicode_8z8z()) and with the Rust library, and
// compares the results. With c_kept, the C output on success is handed to the
// caller (idn2_free() it), otherwise it is freed here
static void check(const enum direction dir, const enum category cat, const char *input,
                  const char *name, const uint32_t cp, char **c_kept)
{
	char *c_text = NULL;
	ftl_rs_buf r_buf = { NULL, 0, 0 };
	int c_rc, r_rc;
	if(dir == TO_ASCII)
	{
		c_rc = idn2_to_ascii_8z(input, &c_text, IDN2_NFC_INPUT | IDN2_NONTRANSITIONAL);
		r_rc = ftl_rs_idn2_to_ascii(input, &r_buf);
	}
	else
	{
		c_rc = idn2_to_unicode_8z8z(input, &c_text, IDN2_NONTRANSITIONAL);
		r_rc = ftl_rs_idn2_to_unicode(input, &r_buf);
	}

	const char *r_text = (const char *)r_buf.ptr;
	bool same = c_rc == r_rc;
	if(same && c_rc == IDN2_OK)
		same = c_text != NULL && r_text != NULL && strcmp(c_text, r_text) == 0;

	inputs[cat]++;
	if(!same)
	{
		char what[1200], c_line[1200], rust_line[1200];
		describe(what, sizeof(what), cat, input, name, cp);
		format_result(c_line, sizeof(c_line), c_rc, c_text, false);
		format_result(rust_line, sizeof(rust_line), r_rc, r_text, true);
		difference(cat, what, c_line, rust_line);
	}

	if(c_kept != NULL && c_rc == IDN2_OK)
		*c_kept = c_text;
	else
		idn2_free(c_text);
	ftl_rs_buf_free(&r_buf);
}

// The messages of the codes -400 to 0, as idn2_strerror() and
// ftl_rs_idn2_strerror() give them
static void check_messages(void)
{
	for(int code = -400; code <= 0; code++)
	{
		inputs[CAT_MESSAGE]++;
		const char *c_message = idn2_strerror(code);
		const char *rust_message = ftl_rs_idn2_strerror(code);
		if(strcmp(c_message, rust_message) != 0)
		{
			char what[32];
			snprintf(what, sizeof(what), "error code %d", code);
			difference(CAT_MESSAGE, what, c_message, rust_message);
		}
	}
}

// Long inputs built at run time: labels of 63 and 64 characters, domains of 253
// and 254 characters, and 70 umlauts in one label
static void check_generated(void)
{
	char label63[64], label64[65];
	memset(label63, 'a', 63);
	label63[63] = '\0';
	memset(label64, 'a', 64);
	label64[64] = '\0';

	char label63_com[80], label64_com[80], domain253[300], domain254[300], umlauts[300];
	snprintf(label63_com, sizeof(label63_com), "%s.com", label63);
	snprintf(label64_com, sizeof(label64_com), "%s.com", label64);
	snprintf(domain253, sizeof(domain253), "%s.%s.%s.%.61s", label63, label63, label63, label63);
	snprintf(domain254, sizeof(domain254), "%s.%s.%s.%.62s", label63, label63, label63, label63);
	size_t len = 0;
	for(int i = 0; i < 70; i++, len += 2)
		memcpy(umlauts + len, "\xc3\xa4", 2);
	memcpy(umlauts + len, ".de", 4);

	const struct golden generated[] = {
		{ "encode 63-character label", TO_ASCII, label63_com },
		{ "encode 64-character label", TO_ASCII, label64_com },
		{ "encode 253-character domain", TO_ASCII, domain253 },
		{ "encode 254-character domain", TO_ASCII, domain254 },
		{ "encode 70 umlauts", TO_ASCII, umlauts },
	};
	for(size_t i = 0; i < sizeof(generated) / sizeof(generated[0]); i++)
		check(generated[i].dir, CAT_GOLDEN, generated[i].input, generated[i].name, 0u, NULL);
}

// pihole-FTL rust-compare idn2: converts the inputs above with the C reference
// and with the Rust library. Prints the first differences and the counts
int ftl_rs_compare_idn2(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	for(uint32_t cp = 0x80u; cp <= 0x10FFFFu; cp++)
	{
		if(cp >= 0xD800u && cp <= 0xDFFFu)
			continue;
		char cp_text[5];
		utf8_encode(cp, cp_text);
		char middle[16], tld[16];
		snprintf(middle, sizeof(middle), "a%sb.com", cp_text);
		snprintf(tld, sizeof(tld), "%s.com", cp_text);
		check(TO_ASCII, CAT_MIDDLE, middle, NULL, cp, NULL);
		char *ascii = NULL;
		check(TO_ASCII, CAT_TLD, tld, NULL, cp, &ascii);
		if(ascii != NULL)
		{
			check(TO_UNICODE, CAT_ROUND_TRIP, ascii, NULL, cp, NULL);
			idn2_free(ascii);
		}
	}

	for(size_t i = 0; i < sizeof(golden_cases) / sizeof(golden_cases[0]); i++)
		check(golden_cases[i].dir, CAT_GOLDEN, golden_cases[i].input, golden_cases[i].name, 0u, NULL);
	check_generated();
	check_messages();

	unsigned int total = 0;
	for(int c = 0; c < CAT_COUNT; c++)
		total += inputs[c];
	if(differences > MAX_DIFFERENCES_SHOWN)
		printf("... %u more differences not shown\n", differences - MAX_DIFFERENCES_SHOWN);
	for(int c = 0; c < CAT_COUNT; c++)
		printf("  %-20s %u inputs, %u differences\n", category_names[c], inputs[c], category_differences[c]);
	printf("rust-compare idn2: %u inputs, %u differences\n", total, differences);
	return differences == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
