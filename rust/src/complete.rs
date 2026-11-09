// Pi-hole: A black hole for Internet advertisements
// (c) 2026 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL Engine
// Rust static library linked into pihole-FTL
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

//! Shell completion for `pihole-FTL --complete`, which the bash completion
//! script calls. Phase 2 module: the rules of suggest_complete_c() in
//! src/args.c. C owns the config. For `--config` it passes a snapshot of every
//! config item (`ftl_rs_conf_entry`, src/ftl_rs.h), and Rust picks the lines
//! to print.

use std::ffi::{c_char, c_int, CStr};
use std::mem::{align_of, offset_of, size_of};
use std::ptr;
use std::slice;

use crate::buf::FtlRsBuf;

// How a config item is completed. Same values as FTL_RS_CONF_* in src/ftl_rs.h.
// Any other value suggests nothing.
const CONF_BOOL: u32 = 1;
const CONF_VALUE: u32 = 2;
const CONF_JSON_ARRAY: u32 = 3;
const CONF_CHOICES: u32 = 4;
const CONF_ALWAYS: u32 = 5;

/// One config item, the C `ftl_rs_conf_entry` of src/ftl_rs.h.
#[repr(C)]
pub struct FtlRsConfEntry {
    key: *const c_char,
    kind: u32,
    default_value: *const c_char,
    choices: *const *const c_char,
    n_choices: usize,
}

/// The root commands, in the order they are printed.
const ROOT_COMMANDS: &[&str] = &[
    "arp-scan", "branch", "backtrace", "crash", "--config", "debug",
    "--default-gateway", "dhcp-discover", "dnsmasq-test", "-f",
    "--gen-x509", "gravity", "gzip", "help", "-h", "--help", "idn2",
    "--list-dhcp4", "--list-dhcp6", "--lua", "--luac", "lua",
    "luac", "ntp", "no-daemon", "--perf", "ptr", "--read-x509",
    "--read-x509-key", "regex-test", "sha256sum", "sqlite3",
    "sqlite3_rsync", "tag", "--teleporter", "test", "--totp",
    "--tls-ciphers", "-v", "-vv", "--v", "version", "verify",
];

/// What a config item suggests after `pihole-FTL --config <key>`.
enum Suggestion<'a> {
    Nothing,
    /// "true" and "false", matched case-insensitively
    Bool,
    /// The default as JSON, if it starts with the word
    Default(&'a [u8]),
    /// The default as a JSON array, quoted for the shell, if it starts with the word
    QuotedDefault(&'a [u8]),
    /// The names of an enum, matched case-insensitively
    Choices(Vec<&'a [u8]>),
    /// Printed whatever the word is
    Always(&'a [u8]),
}

/// A config item as the completion sees it. Borrows from the C snapshot.
struct ConfItem<'a> {
    key: &'a [u8],
    suggestion: Suggestion<'a>,
}

/// Whether `s` starts with `prefix`. An empty prefix matches everything.
fn matches_prefix(s: &[u8], prefix: &[u8], ignore_case: bool) -> bool {
    match s.get(..prefix.len()) {
        Some(head) if ignore_case => head.eq_ignore_ascii_case(prefix),
        Some(head) => head == prefix,
        None => false,
    }
}

fn push_line(out: &mut Vec<u8>, line: &[u8]) {
    out.extend_from_slice(line);
    out.push(b'\n');
}

fn push_if_matches(out: &mut Vec<u8>, candidate: &[u8], word: &[u8], ignore_case: bool) {
    if matches_prefix(candidate, word, ignore_case) {
        push_line(out, candidate);
    }
}

fn push_matching(out: &mut Vec<u8>, word: &[u8], options: &[&str], ignore_case: bool) {
    for option in options {
        push_if_matches(out, option.as_bytes(), word, ignore_case);
    }
}

/// Quotes a JSON default for the shell: '...', with each ' written as '"'"'.
fn shell_quote(json: &[u8]) -> Vec<u8> {
    let mut quoted = Vec::with_capacity(json.len() + 2);
    quoted.push(b'\'');
    for &byte in json {
        if byte == b'\'' {
            quoted.extend_from_slice(b"'\"'\"'");
        } else {
            quoted.push(byte);
        }
    }
    quoted.push(b'\'');
    quoted
}

impl ConfItem<'_> {
    /// The value suggestions for the word being completed.
    fn suggest(&self, out: &mut Vec<u8>, word: &[u8]) {
        match &self.suggestion {
            Suggestion::Nothing => {}
            Suggestion::Bool => push_matching(out, word, &["true", "false"], true),
            Suggestion::Default(json) => push_if_matches(out, json, word, false),
            Suggestion::QuotedDefault(json) => push_if_matches(out, &shell_quote(json), word, false),
            Suggestion::Choices(names) => {
                for name in names {
                    push_if_matches(out, name, word, true);
                }
            }
            Suggestion::Always(text) => push_line(out, text),
        }
    }
}

/// The text to print for the command line `args` (argv of `pihole-FTL
/// --complete`; the last word is the one being completed). `items` is the
/// config snapshot, which only `--config` reads.
fn complete(args: &[&[u8]], items: &[ConfItem]) -> Vec<u8> {
    let mut out = Vec::new();
    let Some(&word) = args.last() else {
        return out;
    };
    let argc = args.len();

    if argc == 4 && args[2].ends_with(b"pihole-FTL") {
        push_matching(&mut out, word, ROOT_COMMANDS, false);
    } else if argc == 5 && args[3].ends_with(b"gravity") {
        push_matching(&mut out, word, &["checkList"], false);
    } else if argc == 5 && args[3].ends_with(b"ntp") {
        push_matching(&mut out, word, &["--update"], false);
    } else if (argc == 5 || argc == 6) && args[3].ends_with(b"sqlite3") {
        let mut options = vec!["-h", "-ni"];
        if argc == 6 {
            // An option already on the line is not offered again
            options.retain(|option| option.as_bytes() != args[4]);
        }
        push_matching(&mut out, word, &options, false);
    } else if argc == 5 && args[3].ends_with(b"arp-scan") {
        push_matching(&mut out, word, &["-a", "-x"], false);
    } else if argc == 5 && args[3].ends_with(b"idn2") {
        push_matching(&mut out, word, &["-d", "--decode"], false);
    } else if argc > 4 && args[3].ends_with(b"--config") {
        match argc {
            // pihole-FTL --config <key prefix>
            5 => {
                for item in items {
                    push_if_matches(&mut out, item.key, word, false);
                }
            }
            // pihole-FTL --config <key> <value prefix>
            6 => {
                for item in items.iter().filter(|item| item.key == args[4]) {
                    item.suggest(&mut out, word);
                }
            }
            _ => {}
        }
    }
    out
}

/// Borrows the C string `p`, or returns None for NULL.
///
/// # Safety
/// `p` is NULL or points to a NUL-terminated string that outlives 'a.
unsafe fn c_str<'a>(p: *const c_char) -> Option<&'a [u8]> {
    if p.is_null() {
        None
    } else {
        Some(CStr::from_ptr(p).to_bytes())
    }
}

/// The argument strings. A NULL argument counts as an empty word, and a NULL
/// `argv` or a negative `argc` as no arguments.
///
/// # Safety
/// `argv` is NULL or points to `argc` pointers, each NULL or a NUL-terminated
/// string that outlives 'a.
unsafe fn c_args<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a [u8]> {
    if argv.is_null() {
        return Vec::new();
    }
    let n = usize::try_from(argc).unwrap_or(0);
    slice::from_raw_parts(argv, n)
        .iter()
        .map(|&arg| c_str(arg).unwrap_or(&[]))
        .collect()
}

/// The choice names of an enum item. NULL names are skipped.
///
/// # Safety
/// `choices` is NULL or points to `n` pointers, each NULL or a NUL-terminated
/// string that outlives 'a.
unsafe fn c_choices<'a>(choices: *const *const c_char, n: usize) -> Vec<&'a [u8]> {
    if choices.is_null() {
        return Vec::new();
    }
    slice::from_raw_parts(choices, n)
        .iter()
        .filter_map(|&name| c_str(name))
        .collect()
}

/// Reads the config snapshot. Entries without a key are skipped, and a NULL
/// default_value leaves nothing to suggest.
///
/// # Safety
/// `entries` is NULL or points to `n` entries whose strings and choice arrays
/// stay valid for 'a.
unsafe fn read_items<'a>(entries: *const FtlRsConfEntry, n: usize) -> Vec<ConfItem<'a>> {
    if entries.is_null() {
        return Vec::new();
    }
    slice::from_raw_parts(entries, n)
        .iter()
        .filter_map(|entry| {
            let key = c_str(entry.key)?;
            let default = c_str(entry.default_value);
            let suggestion = match entry.kind {
                CONF_BOOL => Suggestion::Bool,
                CONF_VALUE => default.map_or(Suggestion::Nothing, Suggestion::Default),
                CONF_JSON_ARRAY => default.map_or(Suggestion::Nothing, Suggestion::QuotedDefault),
                CONF_CHOICES => Suggestion::Choices(c_choices(entry.choices, entry.n_choices)),
                CONF_ALWAYS => default.map_or(Suggestion::Nothing, Suggestion::Always),
                _ => Suggestion::Nothing,
            };
            Some(ConfItem { key, suggestion })
        })
        .collect()
}

/// The completion text for the C arguments, as a Vec.
///
/// # Safety
/// The same as ftl_rs_complete().
unsafe fn complete_c(
    argc: c_int,
    argv: *const *const c_char,
    entries: *const FtlRsConfEntry,
    n_entries: usize,
) -> Vec<u8> {
    let args = c_args(argc, argv);
    let items = read_items(entries, n_entries);
    complete(&args, &items)
}

/// Writes the lines that `pihole-FTL --complete` prints for a command line.
///
/// `argv` holds `argc` strings: `pihole-FTL --complete <program> <words...>`,
/// where the last word is the one being completed. For `--config` C passes
/// the config items in `entries` (in config order) and `n_entries`. Otherwise
/// it passes NULL and 0. The result is the lines to print, each ending in
/// "\n", and may be empty. Free it with ftl_rs_buf_free().
///
/// Locks: none. Never panics.
///
/// # Safety
/// `argv` is NULL or points to `argc` strings, each NULL or NUL-terminated.
/// `entries` is NULL or points to `n_entries` entries. Everything they point
/// to stays valid for the call.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_complete(
    argc: c_int,
    argv: *const *const c_char,
    entries: *const FtlRsConfEntry,
    n_entries: usize,
) -> FtlRsBuf {
    FtlRsBuf::from_vec(complete_c(argc, argv, entries, n_entries))
}

/// Writes the size of `ftl_rs_conf_entry` and the offsets of its five fields
/// to `out[0..6]`, so C can compare them with its own view.
///
/// Locks: none. Never panics.
///
/// # Safety
/// `out` is NULL or points to six writable `size_t`.
#[no_mangle]
pub unsafe extern "C" fn ftl_rs_conf_entry_layout(out: *mut usize) {
    if out.is_null() {
        return;
    }
    let layout = [
        size_of::<FtlRsConfEntry>(),
        offset_of!(FtlRsConfEntry, key),
        offset_of!(FtlRsConfEntry, kind),
        offset_of!(FtlRsConfEntry, default_value),
        offset_of!(FtlRsConfEntry, choices),
        offset_of!(FtlRsConfEntry, n_choices),
    ];
    ptr::copy_nonoverlapping(layout.as_ptr(), out, layout.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buf::ftl_rs_buf_free;
    use std::ffi::CString;

    /// The config items of the tests, in config order.
    fn items() -> Vec<ConfItem<'static>> {
        vec![
            ConfItem {
                key: b"debug.networking",
                suggestion: Suggestion::Bool,
            },
            ConfItem {
                key: b"debug.netlink",
                suggestion: Suggestion::Bool,
            },
            ConfItem {
                key: b"dns.upstreams",
                suggestion: Suggestion::QuotedDefault(br#"["it's","8.8.8.8"]"#),
            },
            ConfItem {
                key: b"dns.port",
                suggestion: Suggestion::Default(b"53"),
            },
            ConfItem {
                key: b"dns.blocking.mode",
                suggestion: Suggestion::Choices(vec![
                    &b"IP"[..],
                    &b"NX"[..],
                    &b"NULL"[..],
                    &b"NODATA"[..],
                ]),
            },
            ConfItem {
                key: b"misc.privacylevel",
                suggestion: Suggestion::Always(b"0"),
            },
            ConfItem {
                key: b"dns.password",
                suggestion: Suggestion::Nothing,
            },
        ]
    }

    /// The output for `pihole-FTL --complete <words...>` with the test items.
    /// The first word is the program.
    fn run(words: &[&str]) -> String {
        let mut args: Vec<&[u8]> = vec!["pihole-FTL".as_bytes(), "--complete".as_bytes()];
        args.extend(words.iter().map(|word| word.as_bytes()));
        String::from_utf8(complete(&args, &items())).unwrap()
    }

    #[test]
    fn root_prefix_matches_case_sensitively() {
        assert_eq!(run(&["pihole-FTL", "versio"]), "version\n");
        assert_eq!(run(&["pihole-FTL", "VERSION"]), "");
    }

    #[test]
    fn root_lists_every_command_for_an_empty_word() {
        let all = run(&["pihole-FTL", ""]);
        let lines: Vec<&str> = all.lines().collect();
        assert_eq!(lines.len(), ROOT_COMMANDS.len());
        assert_eq!(lines[0], "arp-scan");
        assert_eq!(lines[lines.len() - 1], "verify");
    }

    #[test]
    fn root_dash_lists_the_options() {
        assert_eq!(
            run(&["pihole-FTL", "--"]),
            "--config\n--default-gateway\n--gen-x509\n--help\n--list-dhcp4\n\
             --list-dhcp6\n--lua\n--luac\n--perf\n--read-x509\n--read-x509-key\n\
             --teleporter\n--totp\n--tls-ciphers\n--v\n"
        );
    }

    #[test]
    fn other_programs_and_argument_counts_list_nothing() {
        assert_eq!(run(&["pihole", "versio"]), "");
        assert_eq!(run(&["pihole-FTL", "version", ""]), "");
        assert_eq!(run(&["pihole-FTL"]), "");
        assert_eq!(run(&[]), "");
        let args: Vec<&[u8]> = ["pihole-FTL", "--complete", "pihole-FTL", "", "", "", ""]
            .iter()
            .map(|word| word.as_bytes())
            .collect();
        assert_eq!(complete(&args, &items()), b"");
    }

    #[test]
    fn subcommand_options() {
        assert_eq!(run(&["pihole-FTL", "gravity", "c"]), "checkList\n");
        assert_eq!(run(&["pihole-FTL", "gravity", "C"]), "");
        assert_eq!(run(&["pihole-FTL", "ntp", "-"]), "--update\n");
        assert_eq!(run(&["pihole-FTL", "arp-scan", "-"]), "-a\n-x\n");
        assert_eq!(run(&["pihole-FTL", "arp-scan", "-x"]), "-x\n");
        assert_eq!(run(&["pihole-FTL", "idn2", "-"]), "-d\n--decode\n");
        assert_eq!(run(&["pihole-FTL", "idn2", "--d"]), "--decode\n");
    }

    #[test]
    fn sqlite3_does_not_offer_an_option_twice() {
        assert_eq!(run(&["pihole-FTL", "sqlite3", "-"]), "-h\n-ni\n");
        assert_eq!(run(&["pihole-FTL", "sqlite3", "-h", "-"]), "-ni\n");
        assert_eq!(run(&["pihole-FTL", "sqlite3", "-ni", "-"]), "-h\n");
        assert_eq!(run(&["pihole-FTL", "sqlite3", "-x", "-"]), "-h\n-ni\n");
        assert_eq!(run(&["pihole-FTL", "sqlite3", "-h", "x"]), "");
    }

    #[test]
    fn config_lists_the_keys_with_the_prefix() {
        assert_eq!(
            run(&["pihole-FTL", "--config", "debug.ne"]),
            "debug.networking\ndebug.netlink\n"
        );
        assert_eq!(run(&["pihole-FTL", "--config", "debug.netlinkx"]), "");
        assert_eq!(run(&["pihole-FTL", "--config", "Debug."]), "");
        assert_eq!(run(&["pihole-FTL", "--config", ""]).lines().count(), 7);
    }

    #[test]
    fn config_bool_values_ignore_case() {
        assert_eq!(run(&["pihole-FTL", "--config", "debug.networking", "t"]), "true\n");
        assert_eq!(run(&["pihole-FTL", "--config", "debug.networking", "F"]), "false\n");
        assert_eq!(
            run(&["pihole-FTL", "--config", "debug.networking", ""]),
            "true\nfalse\n"
        );
    }

    #[test]
    fn config_default_value_is_suggested_when_it_starts_with_the_word() {
        assert_eq!(run(&["pihole-FTL", "--config", "dns.port", ""]), "53\n");
        assert_eq!(run(&["pihole-FTL", "--config", "dns.port", "5"]), "53\n");
        assert_eq!(run(&["pihole-FTL", "--config", "dns.port", "6"]), "");
    }

    #[test]
    fn config_array_default_is_quoted_for_the_shell() {
        let quoted = r#"'["it'"'"'s","8.8.8.8"]'"#;
        assert_eq!(
            run(&["pihole-FTL", "--config", "dns.upstreams", ""]),
            format!("{quoted}\n")
        );
        assert_eq!(
            run(&["pihole-FTL", "--config", "dns.upstreams", "'"]),
            format!("{quoted}\n")
        );
        // The quote is part of the suggestion, so a bare bracket does not match
        assert_eq!(run(&["pihole-FTL", "--config", "dns.upstreams", "["]), "");
    }

    #[test]
    fn config_enum_names_ignore_case_and_keep_their_order() {
        assert_eq!(
            run(&["pihole-FTL", "--config", "dns.blocking.mode", ""]),
            "IP\nNX\nNULL\nNODATA\n"
        );
        assert_eq!(
            run(&["pihole-FTL", "--config", "dns.blocking.mode", "n"]),
            "NX\nNULL\nNODATA\n"
        );
        assert_eq!(
            run(&["pihole-FTL", "--config", "dns.blocking.mode", "nu"]),
            "NULL\n"
        );
        assert_eq!(run(&["pihole-FTL", "--config", "dns.blocking.mode", "x"]), "");
    }

    #[test]
    fn config_always_value_is_printed_whatever_the_word() {
        assert_eq!(run(&["pihole-FTL", "--config", "misc.privacylevel", ""]), "0\n");
        assert_eq!(run(&["pihole-FTL", "--config", "misc.privacylevel", "zz"]), "0\n");
    }

    #[test]
    fn config_without_suggestions_and_unknown_keys_print_nothing() {
        assert_eq!(run(&["pihole-FTL", "--config", "dns.password", ""]), "");
        assert_eq!(run(&["pihole-FTL", "--config", "nope", ""]), "");
        assert_eq!(run(&["pihole-FTL", "--config", "dns", ""]), "");
    }

    #[test]
    fn more_arguments_after_a_config_key_print_nothing() {
        assert_eq!(
            run(&["pihole-FTL", "--config", "debug.networking", "t", "x"]),
            ""
        );
        assert_eq!(run(&["pihole-FTL", "--config", "debug.networking", "", "x"]), "");
    }

    #[test]
    fn non_matching_word_prints_nothing() {
        assert_eq!(run(&["pihole-FTL", "zzz"]), "");
    }

    #[test]
    fn shell_quote_wraps_and_escapes_quotes() {
        assert_eq!(shell_quote(b"[]"), b"'[]'");
        assert_eq!(shell_quote(b"'"), b"''\"'\"''");
        assert_eq!(shell_quote(b""), b"''");
    }

    #[test]
    fn matches_prefix_handles_empty_and_longer_prefixes() {
        assert!(matches_prefix(b"abc", b"", false));
        assert!(matches_prefix(b"abc", b"ab", false));
        assert!(!matches_prefix(b"abc", b"abcd", false));
        assert!(!matches_prefix(b"", b"a", true));
        assert!(matches_prefix(b"ABC", b"aB", true));
        assert!(!matches_prefix(b"ABC", b"aB", false));
    }

    #[test]
    fn unknown_kind_suggests_nothing() {
        let key = CString::new("dns.port").unwrap();
        let entry = FtlRsConfEntry {
            key: key.as_ptr(),
            kind: 99,
            default_value: key.as_ptr(),
            choices: ptr::null(),
            n_choices: 0,
        };
        let program = CString::new("pihole-FTL").unwrap();
        let config = CString::new("--config").unwrap();
        let word = CString::new("").unwrap();
        let argv = [
            program.as_ptr(),
            program.as_ptr(),
            program.as_ptr(),
            config.as_ptr(),
            key.as_ptr(),
            word.as_ptr(),
        ];
        let out = unsafe { complete_c(6, argv.as_ptr(), &entry, 1) };
        assert!(out.is_empty());
    }

    #[test]
    fn conf_entry_layout_matches_the_c_struct() {
        let pointer = size_of::<*const u8>();
        assert_eq!(size_of::<FtlRsConfEntry>(), 5 * pointer);
        assert_eq!(align_of::<FtlRsConfEntry>(), pointer);
        assert_eq!(offset_of!(FtlRsConfEntry, key), 0);
        assert_eq!(offset_of!(FtlRsConfEntry, kind), pointer);
        assert_eq!(offset_of!(FtlRsConfEntry, default_value), 2 * pointer);
        assert_eq!(offset_of!(FtlRsConfEntry, choices), 3 * pointer);
        assert_eq!(offset_of!(FtlRsConfEntry, n_choices), 4 * pointer);
    }

    #[test]
    fn layout_export_writes_size_and_offsets() {
        let mut out = [0usize; 6];
        unsafe { ftl_rs_conf_entry_layout(out.as_mut_ptr()) };
        let pointer = size_of::<*const u8>();
        assert_eq!(
            out,
            [5 * pointer, 0, pointer, 2 * pointer, 3 * pointer, 4 * pointer]
        );
        // NULL is accepted and does nothing
        unsafe { ftl_rs_conf_entry_layout(ptr::null_mut()) };
    }

    #[test]
    fn c_arguments_and_snapshot_are_read() {
        let program = CString::new("pihole-FTL").unwrap();
        let complete_word = CString::new("--complete").unwrap();
        let config = CString::new("--config").unwrap();
        let key = CString::new("dns.blocking.mode").unwrap();
        let word = CString::new("N").unwrap();
        let argv = [
            program.as_ptr(),
            complete_word.as_ptr(),
            program.as_ptr(),
            config.as_ptr(),
            key.as_ptr(),
            word.as_ptr(),
        ];
        let names: Vec<CString> = ["IP", "NX"]
            .iter()
            .map(|name| CString::new(*name).unwrap())
            .collect();
        let choices: Vec<*const c_char> = names.iter().map(|name| name.as_ptr()).collect();
        let entries = [
            FtlRsConfEntry {
                key: key.as_ptr(),
                kind: CONF_CHOICES,
                default_value: ptr::null(),
                choices: choices.as_ptr(),
                n_choices: choices.len(),
            },
            // An entry without a key is skipped
            FtlRsConfEntry {
                key: ptr::null(),
                kind: CONF_BOOL,
                default_value: ptr::null(),
                choices: ptr::null(),
                n_choices: 0,
            },
        ];
        let out = unsafe { complete_c(argv.len() as c_int, argv.as_ptr(), entries.as_ptr(), entries.len()) };
        assert_eq!(out, b"NX\n");
    }

    #[test]
    fn exported_call_returns_a_buffer_that_can_be_freed() {
        let program = CString::new("pihole-FTL").unwrap();
        let argv = [program.as_ptr(), program.as_ptr(), program.as_ptr(), ptr::null()];
        // A NULL word counts as an empty one, which lists the root commands
        let mut buf = unsafe { ftl_rs_complete(4, argv.as_ptr(), ptr::null(), 0) };
        unsafe { ftl_rs_buf_free(&mut buf) };
        // Freeing again is a no-op
        unsafe { ftl_rs_buf_free(&mut buf) };
    }

    #[test]
    fn survives_null_and_invalid_arguments() {
        let program = CString::new("pihole-FTL").unwrap();
        let argv = [program.as_ptr(), ptr::null(), program.as_ptr(), ptr::null()];
        // NULL words count as empty, and NULL entries as no config items
        let empty_word = run(&["pihole-FTL", ""]);
        assert_eq!(
            unsafe { complete_c(4, argv.as_ptr(), ptr::null(), 3) },
            empty_word.as_bytes()
        );
        // NULL argv and a negative argc print nothing
        assert!(unsafe { complete_c(4, ptr::null(), ptr::null(), 0) }.is_empty());
        assert!(unsafe { complete_c(-1, argv.as_ptr(), ptr::null(), 0) }.is_empty());

        // A NULL default_value suggests nothing for a value kind
        let key = CString::new("dns.port").unwrap();
        let config = CString::new("--config").unwrap();
        let argv = [
            program.as_ptr(),
            program.as_ptr(),
            program.as_ptr(),
            config.as_ptr(),
            key.as_ptr(),
            ptr::null(),
        ];
        let entry = FtlRsConfEntry {
            key: key.as_ptr(),
            kind: CONF_VALUE,
            default_value: ptr::null(),
            choices: ptr::null(),
            n_choices: 0,
        };
        assert!(unsafe { complete_c(6, argv.as_ptr(), &entry, 1) }.is_empty());
    }
}
