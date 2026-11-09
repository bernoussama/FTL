# Rust rewrite plan for FTL

Status: draft, revised after an external review. Base: upstream `pi-hole/FTL` v6.8 (`29c8b13f`).

Line numbers in `test/test_suite.bats` and `test/test_final.bats` refer to the `rust-rewrite` branch after the Phase 0 tagging, not to upstream. `src/` line numbers refer to upstream v6.8.

## Strategy

Replace FTL one module at a time. A Rust static library is linked into the existing `pihole-FTL` binary, and modules move from C to Rust behind an agreed C/Rust boundary. The full existing suite (`test/test_suite.bats` 211 tests, `test/api` 223 pytest cases, `test/test_final.bats` 23 tests) has to pass after every step.

Every module goes through the same loop:

1. **Record the current C behaviour.** Capture normalized C output for the module as golden files, plus a narrow test harness that runs just that module.
2. **Red.** Write Rust tests from the golden files and the module's tagged integration tests. They fail.
3. **Green.** Implement until they pass.
4. **Compare.** Feed the same inputs to the C and Rust versions and diff the results, including fuzzing for parsers. Where the C behaviour is a known security bug, the fixed behaviour is the spec, not the C output.
5. **Switch over.** Turn on the Rust module and run the full suite against both builds.
6. **Delete.** Remove the C code after one stable release.

## Ground rules

- **Shared memory stays owned by C at first.** Rust never holds references into it, because the mappings can move (`MREMAP_MAYMOVE`, `src/shmem.c:1280`) and struct layout (bitfields, sizes) differs by architecture (`src/datastructure.h`). Rust gets opaque handles or copied snapshots.
- **Locks.** Keep the existing process-shared mutexes, which handle a lock holder dying (`src/shmem.c:643`, `:730`). Every exported Rust function documents which locks it expects to be held.
- **Allocation.** Memory is freed by whichever side allocated it. Rust exports its own `*_free` functions and never frees memory from `FTLmalloc`/`FTLfree` (`src/FTL.h:207`, `src/syscalls/free.c`).
- **Panics.** No panic crosses into C. One policy for the whole library: `panic = "abort"`, or `catch_unwind` at every exported function, converted to an error code.
- **Fork safety.** dnsmasq forks TCP workers without exec (`src/dnsmasq/dnsmasq.c:2184`). Rust code must not keep locks, threads or lazily initialized globals across that fork. Add an explicit after-fork hook next to the existing one (`src/dnsmasq_interface.c:4129`).
- **SQLite.** Use FTL's existing SQLite build and its custom extensions (`src/database/sqlite3-ext.c`). Don't bundle a second copy through `rusqlite`.
- **Log strings.** Only strings a test checks are a contract. Classify each one rather than centralizing every message.

## Phase 0: make the tests usable as a spec (no Rust)

- [x] `test/run.sh` accepts `FTL_BIN` and runs locally in `ghcr.io/pi-hole/ftl-build:v2.19` through `test/docker-test.sh` (see `docs/testing.md`).
- [x] Per-module harnesses that set up their own fixtures (tags alone don't create state). Reuse what's already isolated: the CLI tests, the C harnesses, the teleporter restart. Done through `test/golden/record.sh` for sha256, idn2, `--complete` and gzip (Phase 2/3 CLI modules), teleporter (37 cases), config (40), regex (68) and database (38). Cases that need `/etc/pihole` reset it themselves and refuse to run outside docker. Filtering (Phase 7) and the HTTP API (Phase 8) rely on the running-FTL suites.
- [x] Tag each bats test with `test_tags`: `contract`, `log-contract` or `c-impl`.
- [x] Fix the real test defects:
  - `test_suite.bats:654`: the negative check queried `umbrella.ftl` after testing `nxdomain.ede15.ftl`. Fixed.
  - `:707`: tested a bash copy of the MAC-vendor SQL. Now calls `getMACVendor()` through a hidden `pihole-FTL macvendor` subcommand.
  - `:1089`, `:1102`: whole-output `refute_output` could miss a forbidden address among extra lines. Now a multi-line regex (`refute_line` errors on empty output).
  - `:380` (SVCB): the fixture (`test/pdns/setup.sh:106`) stored `port="80"` as the target name with no SvcParams. Fixture changed to `1 . port=80`.
  - Bare `[[ ]]` checks (`:461`–`:640`): now `assert_line`/`refute_line`.
- [x] Keep the four C harnesses (`test/*_regression.c`) runnable. They test timing and allocation, so data files alone can't replace them. Also pull their cases out as shared test vectors. Done for tar, gzip and ptr_response (`test/vectors/`, exported with `--export-vectors`, drift checked by a bats test). txt_stat has none, as dnsmasq stays in C.
- [x] Golden-output recording tool: run the C build on a set of inputs and store normalized outputs, with timestamps, PIDs and the gzip mtime stripped (`test/golden/`).
- **Done when** the suite passes unchanged, module harnesses run on their own, and golden files exist for the Phase 2 modules.

## Phase 1: toolchain spike and boundary rules

- [x] Build an empty Rust library for all 7 CI targets inside the CI containers: amd64 gcc static, amd64 clang, 386, arm/v6, arm/v7, arm64, riscv64. The image doesn't include Rust today, and armv6 and riscv64 musl are the risky ones. If either fails, stop and decide what to do before going further.
  - Done locally (2026-11-08) with `rust/` behind `-DFTL_RUST=ON` and Alpine's `rust`/`cargo` 1.91.1 installed into `ftl-build:v2.19` with `apk add`. The non-amd64 targets ran under QEMU user emulation (binfmt) with the image's native gcc, not a cross build.
  - All 7 build, `pihole-FTL rust-version` prints `ftl-rs 0.1.0 (ABI 1)`, `cargo test` passes, and `test/arch_test.sh` passes (static-pie, 0 shared libraries, CPU/FP checks on arm, backtrace and crash handler).
  - The full suite passes on amd64 with the library linked in (`RUST=1 test/docker-test.sh test`): bats 212/212, pytest 223/223, final 23/23, including the static-linking checks (`:1264`, `:1286`). An earlier run under heavy load (load average ~12 on 4 cores) failed `test_database_query_types_with_range` and `test_08_rate_limiting_enforced`. The first compares two API calls made while FTL may still be writing to the database, so it can fail at random; fix it before relying on the suite for C-vs-Rust comparisons.
  - Rust needs `-lgcc_s -lc` (`native-static-libs`). FTL already links `-static -static-libgcc`, so no extra link flags were needed.
  - Binary size: amd64 grows by about 312 KB (29,093,689 → 29,413,593 bytes) for an almost empty library, mostly Rust std. Track this per module.
  - Under emulation a full build takes 1–1.5 h per target (arm64: 4,869 s), dominated by the SQLite amalgamation. CI should keep native or cross runners for the per-change builds.
  - The toolchain is pinned in a local image built on top of `ftl-build:v2.19` (`test/docker/Dockerfile.rust`, `rust~1.91`, i.e. 1.91.x). `RUST=1` builds use it.
- [x] Write down the boundary rules above. Add ABI checks: `static_assert` struct sizes and offsets in C, plus matching Rust tests, for every type that crosses the boundary.
  - The rules are in `rust/README.md`. The first boundary type is `ftl_rs_buf` (`src/ftl_rs.h`, `rust/src/buf.rs`). Its layout is checked three ways: `_Static_assert` in C, `size_of`/`offset_of!` tests in Rust, and at runtime by `pihole-FTL rust-version`, which fails naming the field that differs. ABI version 2.
- [x] Panic policy, `*_free` functions, and the after-fork hook, tested with a fork stress test.
  - Panics: `panic = "abort"`, no `catch_unwind`. A panic prints its message and the process dies from SIGABRT (exit 134). FTL's crash handler does not cover SIGABRT, so there is no FTL backtrace (`pihole-FTL rust-panic-test`).
  - `ftl_rs_buf_free()` is NULL-safe and resets the buffer, so a double free is a no-op.
  - `ftl_rs_after_fork()` is called in `FTL_TCP_worker_created()` and replaces the process-local state, leaking the old one on purpose. `pihole-FTL rust-fork-test 200` forks children while a second thread keeps the Rust lock busy: 200/200 pass with the hook. Without it, 75/200 passed and 49 hung. The stress test calls the hook itself; the real TCP worker path is covered only by the full suite.
  - Three `c-impl` bats tests cover these and skip on a build without Rust.
- CI approach (local for now, see open decision 2):
  - On each change: native amd64 runs of the C build and the Rust build, plus builds on all architectures.
  - On a schedule: the full suite on all architectures for both builds, plus the C-vs-Rust comparison runs.
  - No combinations of individual per-module switches. At most two builds exist: "all C" and "C with the Rust modules in transition".
- [x] Local CI: `test/ci-local.sh` runs the per-change checks (C and Rust builds, full suite on both, goldens on both, `cargo test`); `--arch`/`--all-arch` add the other platforms.
- **Done when** CI is green everywhere with the empty library, the static-linking checks (`test_suite.bats:1264`, `:1286`) pass, and the fork stress test passes.

## Phases 2 to 10: modules, ordered by risk and dependencies

| # | Module | Notes |
|---|---|---|
| 2 | Small utilities: sha256, idn2, `--complete` | Proves the whole loop end to end. **Done through "Compare" and "Switch over"** (see below). |
| 3 | Archive parsing for teleporter (tar, gzip, zip) | **Exposed to input users upload.** The spec is the reported sizes plus a decompression round trip (`:2294`), not identical compressed bytes (gzip embeds mtime, `src/zip/gzip.c:83`). Port the tar/gzip harness cases. |
| 4 | Config (`pihole.toml`, `FTLCONF_` env vars, validators, `--config`) | Rust works on copied snapshots and C keeps the `lock_shm` swap (`src/config/config.c:259`, `:2193`). Preserve when and how often files get rewritten; the totals in `test_final.bats:47` are scenario-specific and differ on riscv64. |
| 5 | Regex extensions (`;querytype=`, `;reply=`, `;invert`) and the `regex-test` CLI | **Keep TRE in C behind FFI.** It provides approximate matching, backreferences, `(?#)` comments and the exact error text tests check (`:886`–`:1227`). Porting TRE is a separate, optional project. Respect the regex lifetime fixes (`bbe1718e`, `9e1e5065`). |
| 6 | Database: schema, migrations, teleporter import and export | Uses FTL's existing SQLite. Copy the schema SQL verbatim (`:670`). |
| 7 | Filtering decisions: gravity, groups, per-client cache, CNAME inspection, upstream-block detection | Reads shared state through snapshots or handles. Results are cached per client (`:159`–`:195`). Regex state mixes process-local and shared state (`src/regex.c:395`, `:721`). |
| 8 | HTTP API and web server, replacing civetweb; Lua pages via `mlua` against the existing Lua | **Exposed to the network.** The spec is the whole pytest suite (auth, mutations, OpenAPI). Must handle forking explicitly. |
| 9 | Shared-memory rewrite and the global lock | Only after every caller goes through the boundary rules. This is where API-vs-DNS lock contention gets fixed. |
| 10 | NTP, `ptr`, X.509, arp-scan, dhcp-discover | Rewrite X.509 tests that check mbedTLS-specific output (`:2200`, `:2226`) into behaviour tests. |

### Phase 2 status

Done on `rust-rewrite` (2026-11-09). With `-DFTL_RUST=ON` all three modules replace C for every FTL caller; the C code stays compiled as the reference and is deleted after a stable release ("Delete" step).

- sha256: own implementation, no crates. `rust-compare sha256`: 4,177 buffers against nettle, 0 differences. Deliberately differs from C where C had bugs (`skip_end` on a file shorter than 32 bytes, directories and read errors), see `rust/README.md`.
- idn2: the `idna` crate alone was not enough. It implements UTS 46 and accepts names IDNA2008 forbids (`😀.com`), which libidn2 rejects. The port adds the IDNA2008 rules with tables generated from Unicode 15.1.0, and covers the CLI, the list and search API and gravity list parsing (dnsmasq keeps libidn2). `rust-compare idn2`: 2.36 million inputs (every code point in two positions, decode round trips, edge cases, error texts), 0 differences. Not covered: the `_lz` locale conversion (Rust takes UTF-8 only; identical in FTL's UTF-8 setup) and domains near the 255-byte limit after NFC.
- `--complete`: Rust holds the rules, C passes a config snapshot (`ftl_rs_conf_entry`, layout-checked). `rust-compare complete`: 7,838 command lines, byte-identical.
- Goldens (`sha256`, `idn2`, `complete`) pass unchanged on both builds, and the full suite passes on both.
- Binary size (amd64, static): 29,095,353 bytes for C, 30,011,889 with the Rust modules (+916 KB, mostly the Unicode tables of `idna` and the IDNA2008 table).

**Deferred:** dnsmasq stays in C. Budget ongoing work merging upstream dnsmasq releases and keeping FTL's hooks working. If its DNS side is replaced later, the TXT buffer fix (`57878df1`) and the DHCP thread-ownership fix (`f8a939cf`) become requirements to carry over.

**Not rewriting:** the SQLite shell and the Lua interpreter. Rust calls them through wrappers.

## Release gates for each module switch-over

- Latency, throughput, RAM and shared-memory use on a Pi Zero or Pi 3 class device, compared against the C build.
- Lock contention while lists reload, with dashboard API load running at the same time.
- Fork stress tests and sanitizer builds (ASan/UBSan for C, Miri for Rust where it works).
- Fuzzing for every parser that has moved to Rust.
- Real DHCP tests. DHCP is disabled in the fixtures (`test/pihole.toml:561`), so it is effectively untested today. Write these before any dnsmasq work.

## Open decisions

1. Rewrite tests that check C-specific output (civetweb option dump `:2461`, mbedTLS X.509 fields, backtrace symbols `:795`–`:828`, dnsmasq Features line `:61`) to check behaviour instead. Recommended: yes.
2. ~~Whether this is meant to be merged into pi-hole/FTL.~~ Decided (2026-11-08): no upstreaming for now. The work stays on the fork's local `rust-rewrite` branch, so "CI" below means the local docker scripts (`test/ci-local.sh`), not GitHub Actions. Revisit before proposing anything upstream.
3. Whether porting the TRE regex engine is ever worth doing, or whether it stays in C permanently.
