# ftl-rs

Rust parts of FTL, built as a static library and linked into `pihole-FTL`
(see `docs/rust-rewrite-plan.md`). The C declarations are in `src/ftl_rs.h`.
With `-DFTL_RUST=ON`, the modules below replace their C versions for
every FTL caller; without it, FTL is the plain C build.

## Building

Off by default. Enable it with the CMake option `FTL_RUST`:

```sh
./build.sh "-DFTL_RUST=ON"
./pihole-FTL rust-version     # ftl-rs 0.1.0 (ABI 4), then the layout checks
```

CMake runs `cargo build --release --locked --offline` from `rust/` (target
directory inside the build directory) and links `libftl_rs.a` into
`pihole-FTL`.

In the docker wrapper, `RUST=1 test/docker-test.sh build` does the same inside
`ftl-build-rust:v2.19`. The upstream build image
(`ghcr.io/pi-hole/ftl-build:v2.19`) has no Rust toolchain, so that image is
built from `test/docker/Dockerfile.rust` on first use. It adds Alpine's rust and
cargo pinned to 1.91 (1.91.1 on Alpine 3.23), which exist for every CI
architecture. See `docs/testing.md`.

`test/docker-test.sh cargo-test` runs `cargo test --offline` for this crate in
that image, so the Rust unit tests run on their own.

## Dependencies

Third-party crates are vendored in `vendor/` and `.cargo/config.toml` points
cargo there, so builds never touch the network. Currently: `idna` 1.1 with
`idna_adapter` 1.1 (the unicode-rs back end, not ICU4X) and their
dependencies, and `miniz_oxide` 0.8 (DEFLATE, with `adler2`), all
MIT/Apache-2.0 (plus Unicode-3.0 data and Zlib for `miniz_oxide`). To change them, edit
`Cargo.toml`, then in the Rust image with network access run
`cargo generate-lockfile && cargo vendor --versioned-dirs vendor`, and review
the diff of `vendor/`. Add a crate only when writing it ourselves is not
reasonable.

## Modules

Each module replaces a C module when `FTL_RUST` is on. The C version stays
compiled as the reference, and `pihole-FTL rust-compare <module>` runs both on
the same inputs and must report `0 differences`.

- **sha256** (`src/sha256.rs`): FIPS 180-4 SHA-256 without dependencies, for
  `pihole-FTL sha256sum`, the config checksums and the binary self-check
  (`sha256sum()` in `src/files.c`). Files are read to EOF; with `skip_end` the
  last 32 bytes are held back. Deliberate differences from C, which had bugs
  here: a file shorter than 32 bytes with `skip_end` hashes as empty (C
  underflowed and hashed everything), and a directory or a read error is an
  error (C returned a hash of what it had read).
- **idn** (`src/idn.rs`, `src/idn/`): IDNA conversion for `pihole-FTL idn2`, the
  list and search API and gravity list parsing (dnsmasq keeps libidn2). A port
  of libidn2 2.3.8 lookup with `IDN2_NONTRANSITIONAL`: TR46 mapping plus the
  IDNA2008 rules, with libidn2's error codes and messages. `src/idn/tables.rs`
  is generated from the Unicode 15.1.0 files in `data/` by
  `tools/gen_idna2008.py` (do not edit it by hand). Input must be UTF-8.
  `rust-compare idn2` checks every code point, round trips and error texts
  (2.36 million inputs).
- **complete** (`src/complete.rs`): `pihole-FTL --complete`. Rust holds the
  completion rules; C passes a snapshot of the config items
  (`ftl_rs_conf_entry`, layout-checked by `rust-version`) only for `--config`.
  Output is byte-identical to `suggest_complete_c()` (`rust-compare complete`).

The archive modules (Phase 3) read files users upload (teleporter import), so
they treat every size field as untrusted: offsets are checked against the real
buffer, nothing is allocated from a declared size beyond the C limits, and
each has a deterministic mutation test (bit flips, truncations, edited size
fields) in `cargo test` and in its `rust-compare` driver, where the C side runs
in a forked child so a C crash is reported instead of ending the run.

- **tar** (`src/tar.rs`, `src/tar/`): the ustar reader for teleporter import
  (`find_file_in_tar()` and `list_files_in_tar()` in `src/zip/tar.c`). Rust
  returns offsets into the caller's buffer (`ftl_rs_tar_entry`), C builds the
  cJSON. Same accept and reject rules as C (the header checksum is not checked
  there either). `rust-compare tar`: the 45 vectors, 88 generated archives and
  4,000 mutants, 0 differences.
- **gzip** (`src/gzip.rs`, `src/gzip/`): gzip on `miniz_oxide`, for
  `pihole-FTL gzip`/`gunzip` and the teleporter's v5 `.tar.gz` import
  (`inflate_buffer()`, `deflate_file()`, `inflate_file()` in `src/zip/gzip.c`).
  Header, footer and ISIZE checks and their messages follow C; an ISIZE of 0 or
  above 256 MiB is refused before allocating. The contract is the round trip,
  not identical compressed bytes. One documented difference: a corrupt body
  with an incomplete code-length table is rejected by both, as "buf error" by
  C's miniz (which accepts such tables) and as "data error" by Rust.
  `rust-compare gzip` counts these separately and reports 0 other differences.
- **zip** (`src/zip.rs`, `src/zip/`): the teleporter ZIP container. C keeps the
  teleporter logic and calls `ftl_rs_zip_*` (reader and writer handles,
  `ftl_rs_zip_stat`, miniz's error codes and texts) through small adapters in
  `src/zip/teleporter.c`. Own CRC-32, stored and deflate members. The writer
  emits no ZIP64 (at most 65,535 members and 4 GiB). Documented differences
  from miniz: a member marked as a directory, or with no compressed data but a
  non-zero size, fails extraction (miniz reports success and leaves the buffer
  untouched, so teleporter would import uninitialised memory); data running
  past the end of the archive is an error; `validate` checks only what the
  writer produces. `rust-compare zip`: C-written archives read by Rust and the
  reverse, plus 4,272 mutants, 0 differences.

## Rules

- **ABI.** Bump `ABI_VERSION` in `src/lib.rs` and `FTL_RS_ABI_VERSION` in
  `src/ftl_rs.h` together whenever something crossing the boundary changes.
  `pihole-FTL rust-version` fails if they differ. Every type that crosses the
  boundary is checked at compile time in C (`_Static_assert` on size and
  offsets in `src/ftl_rs.h`) and in Rust (unit tests with `size_of`,
  `align_of` and `offset_of!`). At runtime, `ftl_rs_buf_layout()` reports the
  Rust view and `rust-version` compares it with `sizeof` and `offsetof`.
- **Allocation.** Whoever allocates frees. Rust hands out `ftl_rs_buf` and C
  releases it with `ftl_rs_buf_free()`. That function is NULL-safe and resets
  the struct to `{NULL, 0, 0}`, so a second call does nothing. C never calls
  `free()` on a Rust buffer.
- **Panics.** `panic = "abort"` in every profile, so no panic unwinds into C.
  With abort, `catch_unwind` is not needed. A panic prints its message on
  stderr and the process ends with `SIGABRT` (status 134 in a shell). FTL's
  crash handler covers SEGV, BUS, ILL and FPE only, so no FTL backtrace is
  printed. `pihole-FTL rust-panic-test` checks this.
- **Locks.** The library keeps no threads. Every exported function documents
  which FTL locks it expects to be held. No lock is held across a call that
  returns to C.
- **Fork.** dnsmasq forks TCP workers without exec, and a child keeps only the
  forking thread. `FTL_TCP_worker_created()` calls `ftl_rs_after_fork()` before
  the child touches the library. The hook swaps the process-local state
  (`rust/src/fork.rs`) for a fresh one, so a lock that another parent thread
  held at fork time cannot block the child. The old state is leaked on
  purpose. Any new lazily initialised per-process state must be reset here too.

## Test exports

`ftl_rs_selftest_*` exist only for the hidden `pihole-FTL rust-*` subcommands
(`src/args.c`, `src/ftl_rs_selftest.c`). They are not an API.

`pihole-FTL rust-fork-test <N>` starts a thread that takes the process-local
lock in a loop, forks N children, and each child calls the hook and then uses
the library. It prints `rust fork test: N/N children ok` and fails if a child
fails, or if children are still running after 30 s.
