#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Build and test FTL locally inside the CI build container
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# test/run.sh is destructive (kills pihole-FTL, deletes /etc/pihole, creates a
# pihole user, ...). Never run it on the host; use this wrapper instead. The
# source tree is copied into a throwaway container, so neither the host system
# nor the checkout is modified (apart from the build output directory).
#
# Usage: test/docker-test.sh <command> [args]
#
#   build            Build pihole-FTL and the C regression harnesses.
#                    Output goes to ${OUT_DIR} (default: build-docker/).
#   test [bats args] Build (unless FTL_BIN is set), then run test/run.sh.
#                    Extra arguments are passed to both bats runs, e.g.
#                      test/docker-test.sh test --filter-tags contract
#                      test/docker-test.sh test --filter 'Regex Test'
#   shell            Open a shell in a prepared container (source in /app,
#                    binary already staged as /app/pihole-FTL).
#   golden [--check] [module...]
#                    Record golden outputs of the C build into
#                    test/golden/expected/ (default), or with --check compare
#                    the binary under test against them. See
#                    test/golden/record.sh.
#   run <cmd...>     Run a command in a prepared container, e.g.
#                      test/docker-test.sh run ./pihole-FTL -vv
#   cargo-test [args]
#                    Run cargo test for rust/ in the Rust build image. The
#                    checkout is mounted read-only and rust/ is copied to /tmp
#                    first. Extra arguments go to cargo test.
#
# Environment:
#   FTL_BIN      Host path of a pihole-FTL binary to test instead of building.
#                The C regression harnesses (tar_regression, ...) are taken
#                from the same directory if present.
#   OUT_DIR      Host directory for build output (default: build-docker/).
#   SKIP_PYTEST  1 = skip the pytest API tests.
#   LOG_DIR      Host directory to copy FTL/dnsmasq logs to after the run
#                (default: ${OUT_DIR}/logs).
#   GDB          1 = attach gdb to FTL (see test/run.sh).
#   BUILD_OPTS   Extra build.sh options, e.g. "clang" (also sets STATIC=false).
#   RUST         1 = link the Rust library (rust/) into pihole-FTL
#                (-DFTL_RUST=ON). Uses the Rust build image (see IMAGE).
#   IMAGE        Build image. Default: ghcr.io/pi-hole/ftl-build:v2.19, or with
#                RUST=1 (and for cargo-test) ftl-build-rust:v2.19, with a
#                -<platform> suffix when PLATFORM is set. The local Rust image
#                is built from test/docker/Dockerfile.rust the first time it is
#                needed. To rebuild it, remove it with docker rmi. An IMAGE you
#                set yourself is used as it is and never built here.
#   PLATFORM     Docker platform (default: native), e.g. linux/arm64.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$(realpath -m "${OUT_DIR:-${REPO}/build-docker}")"
LOG_DIR="$(realpath -m "${LOG_DIR:-${OUT_DIR}/logs}")"
CACHE_VOLUME="${CACHE_VOLUME:-ftl-cmake-cache}"
BUILD_OPTS="${BUILD_OPTS:-}"
STATIC="true"
if [[ "${BUILD_OPTS}" == *clang* ]]; then
  STATIC="false"
  CACHE_VOLUME="${CACHE_VOLUME}-clang"
fi
RUST="${RUST:-}"
CMAKE_EXTRA=""
if [[ "${RUST}" == "1" ]]; then
  CMAKE_EXTRA="-DFTL_RUST=ON"
  CACHE_VOLUME="${CACHE_VOLUME}-rust"
fi
PLATFORM="${PLATFORM:-}"
if [[ -n "${PLATFORM}" ]]; then
  CI_ARCH="${PLATFORM}"
  CACHE_VOLUME="${CACHE_VOLUME}-${PLATFORM//\//-}"
else
  case "$(uname -m)" in
    x86_64) CI_ARCH="linux/amd64" ;;
    aarch64) CI_ARCH="linux/arm64" ;;
    *) CI_ARCH="" ;;
  esac
fi

cmd="${1:-}"
[[ $# -gt 0 ]] && shift

# Build image: the upstream one, or the local Rust image for RUST=1 and
# cargo-test. An IMAGE set in the environment is used as it is.
BUILD_RUST_IMAGE=false
if [[ -z "${IMAGE:-}" ]]; then
  if [[ "${RUST}" == "1" || "${cmd}" == "cargo-test" ]]; then
    IMAGE="ftl-build-rust:v2.19"
    [[ -n "${PLATFORM}" ]] && IMAGE+="-${PLATFORM//\//-}"
    BUILD_RUST_IMAGE=true
  else
    IMAGE="ghcr.io/pi-hole/ftl-build:v2.19"
  fi
fi

docker_args=(--rm -i -e "TERM=xterm" -e "CI_ARCH=${CI_ARCH}" -e "STATIC=${STATIC}"
             -e "BUILD_OPTS=${BUILD_OPTS}" -v "${REPO}:/src:ro")
[[ -t 0 && -t 1 ]] && docker_args+=(-t)
[[ -n "${PLATFORM}" ]] && docker_args+=(--platform "${PLATFORM}")

# Copy the checkout into /app without build directories or local artifacts.
# GNU tar keeps mtimes, so incremental builds in the cache volume still work.
# Files end up owned by root, which keeps git from complaining about ownership.
copy_source='tar -C /src --exclude=./cmake --exclude=./cmake_ci --exclude=./build-docker --exclude=./build-ci \
  --exclude=./test/libs --exclude=./rust/target --exclude=./node_modules --exclude="./pihole-FTL*" -cf - . \
  | tar -C /app --no-same-owner -xf -'

REGRESSION_HARNESSES="tar_regression gzip_regression ptr_response_regression txt_stat_regression"
REGRESSION_FLAGS="-DBUILD_TAR_REGRESSION=ON -DBUILD_GZIP_REGRESSION=ON -DBUILD_PTR_RESPONSE_REGRESSION=ON -DBUILD_TXT_STAT_REGRESSION=ON"

# Build the local Rust image if it does not exist yet (see IMAGE above)
ensure_rust_image() {
  [[ "${BUILD_RUST_IMAGE}" == "true" ]] || return 0
  if docker image inspect "${IMAGE}" > /dev/null 2>&1; then
    return 0
  fi
  local -a platform_args=()
  if [[ -n "${PLATFORM}" ]]; then
    platform_args=(--platform "${PLATFORM}")
  fi
  echo "Building ${IMAGE} from test/docker/Dockerfile.rust"
  docker build "${platform_args[@]}" -t "${IMAGE}" \
    -f "${REPO}/test/docker/Dockerfile.rust" "${REPO}/test/docker"
}

do_build() {
  ensure_rust_image
  mkdir -p "${OUT_DIR}"
  echo "Building FTL in ${IMAGE} (cache volume: ${CACHE_VOLUME}, output: ${OUT_DIR})"
  # shellcheck disable=SC2016
  docker run "${docker_args[@]}" -v "${CACHE_VOLUME}:/app/cmake" -v "${OUT_DIR}:/out" \
    -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" "${IMAGE}" bash -c "
      set -e
      mkdir -p /app && ${copy_source}
      cd /app
      # Not \"build.sh test\": that would also run the test suite
      bash build.sh '-DSTATIC=${STATIC} ${REGRESSION_FLAGS} ${CMAKE_EXTRA}' ${BUILD_OPTS}
      for f in pihole-FTL ${REGRESSION_HARNESSES}; do
        [ -f \"\$f\" ] && cp \"\$f\" /out/
      done
      chown \"\${HOST_UID}:\${HOST_GID}\" /out/*
    " < /dev/null
}

# Pick the binary under test and print its path
binary_under_test() {
  if [[ -n "${FTL_BIN:-}" ]]; then
    realpath "${FTL_BIN}"
  else
    echo "${OUT_DIR}/pihole-FTL"
  fi
}

# Run a script inside a fresh container with the source in /app and the binary
# under test (and the regression harnesses next to it) mounted at /ftl-bin
run_prepared() {
  local bin script
  bin="$(binary_under_test)"
  script="${1}"
  if [[ ! -x "${bin}" ]]; then
    echo "No binary at ${bin}; run '$0 build' or set FTL_BIN" >&2
    exit 1
  fi
  ensure_rust_image
  mkdir -p "${LOG_DIR}"
  docker run "${docker_args[@]}" "${extra_mounts[@]}" -v "$(dirname "${bin}"):/ftl-bin:ro" -v "${LOG_DIR}:/logs" \
    -e "FTL_BIN=/ftl-bin/$(basename "${bin}")" -e "SKIP_PYTEST=${SKIP_PYTEST:-}" -e "GDB=${GDB:-}" -e "BATS_ARGS=${BATS_ARGS:-}" \
    -e "NO_UPLOAD=1" -e "LOG_DIR=/logs" -e "HOST_UID=$(id -u)" -e "HOST_GID=$(id -g)" \
    "${IMAGE}" bash -c "
      set -e
      mkdir -p /app && ${copy_source}
      cd /app
      cp \"\${FTL_BIN}\" ./pihole-FTL
      # The C regression harnesses are picked up from next to the binary
      for f in ${REGRESSION_HARNESSES}; do
        [ -f \"/ftl-bin/\$f\" ] && cp \"/ftl-bin/\$f\" ./
      done
      ${script}
    "
}

# cargo test for rust/ in the Rust image. rust/ is copied to /tmp (without
# target/) so that cargo never writes into the mounted checkout.
cargo_test() {
  ensure_rust_image
  docker run "${docker_args[@]}" "${IMAGE}" bash -c '
    set -e
    mkdir -p /tmp/ftl-rs
    tar -C /src/rust --exclude=./target -cf - . | tar -C /tmp/ftl-rs -xf -
    cd /tmp/ftl-rs
    cargo test --locked --offline "$@"
  ' bash "$@" < /dev/null
}

extra_mounts=()

case "${cmd}" in
  build)
    do_build
    ;;
  test)
    if [[ -z "${FTL_BIN:-}" ]]; then
      do_build
    fi
    printf -v bats_args '%q ' "$@"
    [[ $# -eq 0 ]] && bats_args=""
    # run.sh returns non-zero on test failures; still fix log ownership
    export BATS_ARGS="${bats_args}"
    run_prepared "set +e
      bash test/run.sh
      ret=\$?
      chown -R \"\${HOST_UID}:\${HOST_GID}\" /logs
      exit \$ret"
    ;;
  shell)
    run_prepared "exec bash"
    ;;
  golden)
    mkdir -p "${REPO}/test/golden/expected"
    extra_mounts=(-v "${REPO}/test/golden/expected:/golden")
    printf -v golden_args '%q ' "$@"
    [[ $# -eq 0 ]] && golden_args=""
    run_prepared "set +e
      FTL=./pihole-FTL GOLDEN_DIR=/golden bash test/golden/record.sh ${golden_args}
      ret=\$?
      chown -R \"\${HOST_UID}:\${HOST_GID}\" /golden /logs
      exit \$ret"
    ;;
  run)
    printf -v user_cmd '%q ' "$@"
    run_prepared "${user_cmd}"
    ;;
  cargo-test)
    cargo_test "$@"
    ;;
  *)
    sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    [[ "${cmd}" == "-h" || "${cmd}" == "help" ]] && exit 0
    exit 1
    ;;
esac
