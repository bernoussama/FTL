# ftl-rs

Rust parts of FTL, built as a static library and linked into `pihole-FTL`
(see `docs/rust-rewrite-plan.md`). So far this is the Phase 1 boundary: ABI
and layout checks, the allocation, panic and fork rules, and a fork stress
test. No FTL module lives here yet. The C declarations are in `src/ftl_rs.h`.

## Building

Off by default. Enable it with the CMake option `FTL_RUST`:

```sh
./build.sh "-DFTL_RUST=ON"
./pihole-FTL rust-version     # ftl-rs 0.1.0 (ABI 2), then the ftl_rs_buf layout check
```

CMake runs `cargo build --release --locked --offline` in the build directory
and links `libftl_rs.a` into `pihole-FTL`.

In the docker wrapper, `RUST=1 test/docker-test.sh build` does the same inside
`ftl-build-rust:v2.19`. The upstream build image
(`ghcr.io/pi-hole/ftl-build:v2.19`) has no Rust toolchain, so that image is
built from `test/docker/Dockerfile.rust` on first use. It adds Alpine's rust and
cargo pinned to 1.91 (1.91.1 on Alpine 3.23), which exist for every CI
architecture. See `docs/testing.md`.

`test/docker-test.sh cargo-test` runs `cargo test --offline` for this crate in
that image, so the Rust unit tests run on their own.

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
