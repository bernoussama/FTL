# Rust rewrite plan for FTL

Status: draft, revised after an external review. Base: upstream `pi-hole/FTL` v6.8 (`29c8b13f`).

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

- `test/run.sh` accepts `FTL_BIN` and runs locally in `ghcr.io/pi-hole/ftl-build:v2.19`.
- Per-module harnesses that set up their own fixtures (tags alone don't create state). Reuse what's already isolated: the CLI tests, the C harnesses, the teleporter restart.
- Tag each bats test with `test_tags`: `contract`, `log-contract` or `c-impl`.
- Fix the real test defects:
  - `test_suite.bats:628`: the negative check queries `umbrella.ftl` after testing `nxdomain.ede15.ftl`.
  - `:677`: tests a bash copy of the MAC-vendor SQL; make it call FTL's real code.
  - `:1015`, `:1025`: whole-output `refute_output` can miss a forbidden address among extra lines; switch to per-line checks.
  - `:328` (SVCB): investigate against what the fixture intends (`test/pdns/setup.sh:106`) before changing anything.
  - Bare `[[ ]]` checks (`:399`–`:609`): turn into `assert_*` for better failure messages.
- Keep the four C harnesses (`test/*_regression.c`) runnable. They test timing and allocation, so data files alone can't replace them. Also pull their cases out as shared test vectors.
- Golden-output recording tool: run the C build on a set of inputs and store normalized outputs, with timestamps, PIDs and the gzip mtime stripped.
- **Done when** the suite passes unchanged, module harnesses run on their own, and golden files exist for the Phase 2 modules.

## Phase 1: toolchain spike and boundary rules

- Build an empty Rust library for all 7 CI targets inside the CI containers: amd64 gcc static, amd64 clang, 386, arm/v6, arm/v7, arm64, riscv64. The image doesn't include Rust today, and armv6 and riscv64 musl are the risky ones. If either fails, stop and decide what to do before going further.
- Write down the boundary rules above. Add ABI checks: `static_assert` struct sizes and offsets in C, plus matching Rust tests, for every type that crosses the boundary.
- Panic policy, `*_free` functions, and the after-fork hook, tested with a fork stress test.
- CI approach:
  - On each change: native amd64 runs of the C build and the Rust build, plus builds on all architectures.
  - On a schedule: the full suite on all architectures for both builds, plus the C-vs-Rust comparison runs.
  - No combinations of individual per-module switches. At most two builds exist: "all C" and "C with the Rust modules in transition".
- **Done when** CI is green everywhere with the empty library, the static-linking checks (`test_suite.bats:1166`, `:1187`) pass, and the fork stress test passes.

## Phases 2 to 10: modules, ordered by risk and dependencies

| # | Module | Notes |
|---|---|---|
| 2 | Small utilities: sha256, idn2, `--complete` | Proves the whole loop end to end. The `idna` crate supports the non-transitional mode `:1611` needs (ß stays ß). |
| 3 | Archive parsing for teleporter (tar, gzip, zip) | **Exposed to input users upload.** The spec is the reported sizes plus a decompression round trip (`:2129`), not identical compressed bytes (gzip embeds mtime, `src/zip/gzip.c:83`). Port the tar/gzip harness cases. |
| 4 | Config (`pihole.toml`, `FTLCONF_` env vars, validators, `--config`) | Rust works on copied snapshots and C keeps the `lock_shm` swap (`src/config/config.c:259`, `:2193`). Preserve when and how often files get rewritten; the totals in `test_final.bats:31` are scenario-specific and differ on riscv64. |
| 5 | Regex extensions (`;querytype=`, `;reply=`, `;invert`) and the `regex-test` CLI | **Keep TRE in C behind FFI.** It provides approximate matching, backreferences, `(?#)` comments and the exact error text tests check (`:844`–`:1133`). Porting TRE is a separate, optional project. Respect the regex lifetime fixes (`bbe1718e`, `9e1e5065`). |
| 6 | Database: schema, migrations, teleporter import and export | Uses FTL's existing SQLite. Copy the schema SQL verbatim (`:642`). |
| 7 | Filtering decisions: gravity, groups, per-client cache, CNAME inspection, upstream-block detection | Reads shared state through snapshots or handles. Results are cached per client (`:132`–`:162`). Regex state mixes process-local and shared state (`src/regex.c:395`, `:721`). |
| 8 | HTTP API and web server, replacing civetweb; Lua pages via `mlua` against the existing Lua | **Exposed to the network.** The spec is the whole pytest suite (auth, mutations, OpenAPI). Must handle forking explicitly. |
| 9 | Shared-memory rewrite and the global lock | Only after every caller goes through the boundary rules. This is where API-vs-DNS lock contention gets fixed. |
| 10 | NTP, `ptr`, X.509, arp-scan, dhcp-discover | Rewrite X.509 tests that check mbedTLS-specific output (`:2039`, `:2064`) into behaviour tests. |

**Deferred:** dnsmasq stays in C. Budget ongoing work merging upstream dnsmasq releases and keeping FTL's hooks working. If its DNS side is replaced later, the TXT buffer fix (`57878df1`) and the DHCP thread-ownership fix (`f8a939cf`) become requirements to carry over.

**Not rewriting:** the SQLite shell and the Lua interpreter. Rust calls them through wrappers.

## Release gates for each module switch-over

- Latency, throughput, RAM and shared-memory use on a Pi Zero or Pi 3 class device, compared against the C build.
- Lock contention while lists reload, with dashboard API load running at the same time.
- Fork stress tests and sanitizer builds (ASan/UBSan for C, Miri for Rust where it works).
- Fuzzing for every parser that has moved to Rust.
- Real DHCP tests. DHCP is disabled in the fixtures (`test/pihole.toml:561`), so it is effectively untested today. Write these before any dnsmasq work.

## Open decisions

1. Rewrite tests that check C-specific output (civetweb option dump `:2234`, mbedTLS X.509 fields, backtrace symbols `:762`–`:793`, dnsmasq Features line `:45`) to check behaviour instead. Recommended: yes.
2. Whether this is meant to be merged into pi-hole/FTL. If so, raise it with the maintainers before Phase 1, because it adds a Rust toolchain to every CI architecture.
3. Whether porting the TRE regex engine is ever worth doing, or whether it stays in C permanently.
