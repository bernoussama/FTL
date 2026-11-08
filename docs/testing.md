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
has binfmt support for it. Neither has been tried yet, only native amd64.

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
