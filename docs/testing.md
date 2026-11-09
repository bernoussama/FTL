# Running the tests locally

`test/run.sh` is destructive. It kills every `pihole-FTL` process, deletes
`/etc/pihole`, `/etc/dnsmasq.d` and `/var/log/pihole`, creates a `pihole` user
and sets file capabilities. **Never run it, bats or pytest directly on the
host.** Use `test/docker-test.sh`, which runs everything in
`ghcr.io/pi-hole/ftl-build:v2.19` (the CI image) on a copy of the checkout.

```sh
test/docker-test.sh build              # build into build-docker/ (cmake cache in a docker volume)
test/docker-test.sh test               # build, then run bats + pytest + final bats
FTL_BIN=build-docker/pihole-FTL test/docker-test.sh test   # test an existing binary, no build
test/docker-test.sh test --filter-tags contract            # extra args go to both bats runs
SKIP_PYTEST=1 test/docker-test.sh test --filter 'Regex Test'
test/docker-test.sh shell              # shell with the source in /app and the binary staged
test/docker-test.sh run ./pihole-FTL -vv
```

Logs (FTL.log, pihole.log, webserver.log, ptr.log, pihole.toml) are copied to
`build-docker/logs/` after a test run. Nothing is uploaded to tricorder.

`BUILD_OPTS=clang` builds with clang (dynamically linked, like the CI clang
job). `PLATFORM=linux/arm64` etc. runs another architecture via QEMU, if docker
has binfmt support for it. `test/ci-local.sh --arch` runs the Rust build on the
other CI platforms (see below).

`test/run.sh` itself also takes:

- `FTL_BIN`: binary under test, copied to `./pihole-FTL` because the tests call
  it by that name
- `BATS_ARGS`: shell-quoted extra bats arguments
- `SKIP_PYTEST=1`, `NO_UPLOAD=1`, `LOG_DIR=<dir>`

## Test tags

Every bats test in `test/test_suite.bats` and `test/test_final.bats` carries one
`# bats test_tags=` tag:

| Tag | Meaning |
|---|---|
| `contract` | Behaviour any implementation must keep: DNS answers, API, CLI output and exit codes, files, database contents |
| `log-contract` | Depends on the text of a log line, including `wait-for` on one |
| `c-impl` | Only meaningful for the C build or a C library's output format (linking, backtraces, mbedTLS/civetweb dumps, the C regression harnesses) |

Precedence when several apply: `c-impl` > `log-contract` > `contract`.

The tests share one running FTL and depend on running in order. A filtered run
(`--filter-tags`) skips the setup that the skipped tests did, and the pytest
suite counts the queries the bats suite sent (`TOTAL` in
`test/api/test_api.py`). Use filters for quick iteration and the full run as the
real check.

## Golden outputs

See `test/golden/README.md`: `test/docker-test.sh golden [--check]`.

## Local CI

`test/ci-local.sh` runs the checks that run on each change (Phase 1 of
`docs/rust-rewrite-plan.md`). CI runs here until the work goes upstream. Each
stage runs through `test/docker-test.sh`.

```sh
test/ci-local.sh                    # default stages, full suite
test/ci-local.sh --quick            # bats only (SKIP_PYTEST=1)
test/ci-local.sh --only rust-test   # one stage
test/ci-local.sh --arch linux/386   # also the Rust build and arch_test.sh on that platform
test/ci-local.sh --all-arch         # all other CI platforms and clang (hours under QEMU)
```

The default stages are `c-build`, `c-test`, `rust-build`, `rust-test`, `golden-c`,
`golden-rust` and `cargo-test`. The C and Rust builds go to `build-ci/c` and
`build-ci/rust`. Each stage logs to `build-ci/logs/<stage>.log`. The run ends
with a table of stage, result and duration, and exits non-zero if a stage
failed. A test stage is skipped when its build failed.

`--quick` fails both test stages on the final bats run: `test/test_final.bats:47`
expects the config writes of the pytest run too (42), so only a full run passes.

Measured on this 4-core machine:

- The C and Rust builds take about 7 and 5 minutes from an empty cache volume,
  and about 10 seconds when incremental.
- Each test stage takes about 4 minutes with pytest.
- `--arch linux/386` took 4.6 minutes, including the first 386 build. 386 runs at
  native speed on amd64. The other platforms run under QEMU and take 1 to 1.5 hours
  each (`docs/rust-rewrite-plan.md`).
- The first `--quick` run from empty caches took 19 minutes. A warm full run
  takes about 10 minutes.

### Rust build image

`RUST=1` and `test/docker-test.sh cargo-test` use `ftl-build-rust:v2.19`, with a
`-<platform>` suffix when `PLATFORM` is set. The first use builds it from
`test/docker/Dockerfile.rust` on top of `ghcr.io/pi-hole/ftl-build:v2.19`.

The Dockerfile installs Alpine's `rust` and `cargo` with the match `~1.91`, so
every build and platform uses the 1.91 series. Alpine 3.23 currently provides
1.91.1-r2. An image built after Alpine ships a newer 1.91 patch release gets
that release. Check the version with:

```sh
docker run --rm ftl-build-rust:v2.19 rustc --version
```

To rebuild the image, for example after a change to the Dockerfile, remove it and
run a `RUST=1` command again:

```sh
docker rmi ftl-build-rust:v2.19
```

Building the image takes about 40 seconds, on amd64 and on arm64 under QEMU.
An `IMAGE` set in the environment is used as it is, and the wrapper never builds it.
