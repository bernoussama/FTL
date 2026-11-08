# ftl-rs

Rust parts of FTL, built as a static library and linked into `pihole-FTL`
(see `docs/rust-rewrite-plan.md`). Right now it is the Phase 1 toolchain
spike: two functions, `ftl_rs_abi_version()` and `ftl_rs_version()`, declared
for C in `src/ftl_rs.h`.

## Building

Off by default. Enable it with the CMake option `FTL_RUST`:

```sh
./build.sh "-DFTL_RUST=ON"
./pihole-FTL rust-version     # ftl-rs 0.1.0 (ABI 1)
```

CMake runs `cargo build --release --locked --offline` into
`cmake/rust/` and links `libftl_rs.a` into `pihole-FTL`. The build image
(`ghcr.io/pi-hole/ftl-build:v2.19`) has no Rust toolchain yet; inside it,
`apk add rust cargo` installs Alpine's Rust (1.91.1 on Alpine 3.23), which
exists for every CI architecture.

`cargo test` runs the Rust unit tests on their own.

## Rules

- `panic = "abort"` in every profile: no panic unwinds into C.
- No dependencies from crates.io for now, so builds work offline.
- Every exported function documents which FTL locks it expects to be held.
- Bump `ABI_VERSION` in `src/lib.rs` and `FTL_RS_ABI_VERSION` in
  `src/ftl_rs.h` together whenever something crossing the boundary changes.
  `pihole-FTL rust-version` fails if they differ.
