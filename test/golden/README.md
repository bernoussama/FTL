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
- `fixtures/`: input files.
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
