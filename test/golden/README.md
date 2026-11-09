# Golden outputs

Recorded outputs of the C build for the modules that get rewritten first. They
are the reference the Rust versions are compared against (Phase 0 of
`docs/rust-rewrite-plan.md`).

| Module | Cases | Plan phase |
|---|---|---|
| `sha256` | `pihole-FTL sha256sum` | 2 |
| `idn2` | `pihole-FTL idn2 [-d]` | 2 |
| `complete` | `pihole-FTL --complete` | 2 |
| `gzip` | `pihole-FTL gzip` | 3 |
| `teleporter` | `pihole-FTL --teleporter` (export), `pihole-FTL --teleporter FILE` (import) | 3 |
| `config` | `pihole-FTL --config [-q\|-t] [key [value]]`, pihole.toml, `FTLCONF_` env vars, validators | 4 |
| `regex` | `pihole-FTL regex-test [-q] str [rgx]` | 5 |
| `database` | FTL start-up on a new, old or broken `pihole-FTL.db`, `pihole-FTL sqlite3`, `subnet_match`/`isIPv6`, `pihole-FTL gravity` | 6 |

## Usage

Always through the docker wrapper (it never touches the host):

```sh
test/docker-test.sh build                       # C build into build-docker/
test/docker-test.sh golden                      # (re)record all modules
test/docker-test.sh golden idn2                 # record one module
FTL_BIN=/path/to/pihole-FTL test/docker-test.sh golden --check      # compare
FTL_BIN=/path/to/pihole-FTL test/docker-test.sh golden --check gzip
```

`--check` prints a unified diff per differing case and exits non-zero.

## Layout

- `cases/<module>.cases`: one case per line, `<name> | <shell command>`. The
  command runs with bash in a fresh copy of `fixtures/`, `$FTL` is the binary.
- `fixtures/`: input files. Modules with more setup keep inputs and helper
  scripts in `fixtures/<module>/`, reachable from a case as
  `./<module>/<script>.sh`.
- `expected/<module>/<name>.out`: exit code, stdout and stderr of each case.

Normalized before storing and comparing: timestamps, PIDs and thread IDs, the
scratch directory, source locations such as `(src/zip/gzip.c:<LINE>)`, and the
gzip header mtime (`gzip_header` prints the header without it).

## What is the spec

Not every byte of a golden file is a requirement. Known exceptions:

- `gzip`: the compressed sizes in the messages come from the C deflate
  implementation. The spec is the round trip and the header fields.
- `gzip/compress-empty` reports `-inf% size reduction` and
  `gzip/decompress-trunc` reports `File is empty or too large` plus a "free NULL
  pointer" warning. These record current C behaviour, not intended behaviour.
  Decide case by case whether the Rust version copies or fixes them, and
  re-record the golden file if it is fixed.

Modules that need system state (`teleporter`, `config`, `database`, and
`regex` with a gravity.db) set up and remove `/etc/pihole` and
`/etc/dnsmasq.d` in every case, and some start FTL briefly. Their helpers
refuse to run outside docker (no `/.dockerenv`), so record them only through
`test/docker-test.sh golden`.

- `teleporter`: the spec is the archive name pattern, the entry names, the
  verbatim text entries, the rows of gravity.db and pihole-FTL.db, and the
  import rules: ZIP only, expected names only, traversal and absolute names
  skipped, and an invalid pihole.toml or gravity.db refused with exit 1. Not
  spec: the message wording, the masked SQLite and /etc/hosts sizes, the exact
  pihole.toml rewrite, and the config_backups rotation. Known C behaviour to
  decide on: the import does not restore the AUTOINCREMENT high-water mark,
  and it is not atomic (a valid pihole.toml earlier in the archive is
  installed before a corrupt gravity.db is refused). The v5 tar.gz import
  exists only in the API, so the CLI rejects it here and only
  `test/api/test_n_teleporter_validation.py` covers it.
- `config`: the spec is the exit code and first message of each rejected
  value or unknown key, the lines written to pihole.toml (values, `###
  CHANGED` markers, env-forced entries, unknown keys dropped on write), the
  backup rotation (`pihole.toml.1` is the state before the last write, at
  most 15 files) and the env rules (`FTLCONF_` keys are case-insensitive, an
  invalid type locks the key with exit 5, an invalid validator value does
  not, arrays are `;`-separated). Not spec: the cJSON error position in the
  bad-JSON message, the statistics lines after `Wrote config file` (printed
  even when nothing changed) and the `migrate v6` log text. Not recorded:
  `dns.hosts` writes reach `hosts/custom.list` one change late, and a write
  with no /etc/pihole returns 0 with warnings.
- `regex`: the exit codes of `regex-test` are the main spec: 0 for a match, 1
  for an invalid regex or a usage error, 2 for no match (including no matching
  database entry or a missing gravity.db). With `-q`, a match or no match
  prints nothing and an invalid regex still prints its error. Approximate
  matching, back references and the TRE error texts are spec (TRE stays in
  C). The `;querytype=`/`;reply=` wording is recorded as is. Known C
  behaviour to decide on: `regex-test` without arguments prints `invalid
  option -- 'regex-test'`, an empty `querytype=` or `reply=` reports
  `Unknown ... ""`, an unknown token in a list such as `A,BOGUS` is ignored if
  another token is valid, and the querytype filter is not applied in CLI mode.
- `database`: the spec is what FTL creates or upgrades and what it leaves on
  disk. A new and an upgraded pihole-FTL.db both reach version 22 with the
  same objects and mode 640, and the v1 and suite-v9 rows are kept. A newer
  (version 23), empty or non-SQLite file is left unchanged and FTL logs
  "database not available". Also spec: the sqlite3 shell options FTL adds,
  `subnet_match`/`isIPv6`, the gravity schema, views and triggers, and
  `gravity checkList`/`parseList`. The schema dumps compare the CREATE text
  as C writes it, whitespace included, so equivalent DDL written differently
  shows up as a diff; the migrated suite-v9 schema keeps fixture text that
  bats asserts on. `sqlite3 -help` and the `.version` strings are SQLite's
  and normalized where they vary. The host "Long-term load" warning is
  filtered out.
