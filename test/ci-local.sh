#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Local CI: the checks that run on each change, through test/docker-test.sh
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# Runs the "on each change" checks of docs/rust-rewrite-plan.md (Phase 1). CI
# runs here, not on GitHub Actions (open decision 2 in the plan). Every stage
# runs in docker through test/docker-test.sh, never on the host. Each stage
# writes its output to build-ci/logs/<stage>.log, and the run ends with a
# summary table. Stages keep going after a failure; the exit code is non-zero
# if any stage failed.
#
# Usage: test/ci-local.sh [options]
#
#   (no option)      Stages: c-build c-test rust-build rust-test golden-c
#                    golden-rust cargo-test. The suite runs in full (bats,
#                    pytest and the final bats run).
#   --quick          Skip pytest (SKIP_PYTEST=1), run the bats suites only.
#   --only <stage>   Run only this stage. Stages that test a build expect that
#                    build in build-ci/ from an earlier run.
#   --arch <platform>[,<platform>...]
#                    Add a Rust build for each platform, followed by
#                    rust-version and test/arch_test.sh in a container of that
#                    platform. Platforms: linux/386, linux/arm/v6, linux/arm/v7,
#                    linux/arm64, linux/riscv64. Emulated platforms take 1-1.5 h
#                    each.
#   --all-arch       --arch for all of those platforms, plus the amd64 clang
#                    build (BUILD_OPTS=clang). Several hours.
#   -h, --help       Show this help.
#
# Stage names: c-build, c-test, rust-build, rust-test, golden-c, golden-rust,
# cargo-test, arch-<platform> (e.g. arch-linux-386, arch-linux-arm-v6) and
# arch-linux-amd64-clang.
#
# Outputs: build-ci/c, build-ci/rust, build-ci/rust-<platform>,
# build-ci/rust-linux-amd64-clang (binaries and each run's logs), and
# build-ci/logs/. The CMake caches are the docker volumes ftl-cmake-ci,
# suffixed by test/docker-test.sh for each build variant.
#
# The environment variables of test/docker-test.sh (IMAGE, PLATFORM, RUST,
# BUILD_OPTS, ...) are cleared for every stage, so the stages always use the
# default images and their own settings.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DT="${REPO}/test/docker-test.sh"
OUT_ROOT="${REPO}/build-ci"
LOG_ROOT="${OUT_ROOT}/logs"
CI_PLATFORMS=(linux/386 linux/arm/v6 linux/arm/v7 linux/arm64 linux/riscv64)

quick=false
only=""
arch_list=()
all_arch=false

usage() {
  sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "$*" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick)
      quick=true
      ;;
    --only)
      [[ $# -ge 2 ]] || die "--only needs a stage name"
      only="$2"
      shift
      ;;
    --arch)
      [[ $# -ge 2 ]] || die "--arch needs a platform list"
      IFS=',' read -ra requested <<< "$2"
      for p in "${requested[@]}"; do
        [[ " ${CI_PLATFORMS[*]} " == *" ${p} "* ]] \
          || die "Unknown platform ${p} (CI platforms: ${CI_PLATFORMS[*]})"
        [[ " ${arch_list[*]:-} " == *" ${p} "* ]] || arch_list+=("${p}")
      done
      shift
      ;;
    --all-arch)
      all_arch=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "Unknown option $1"
      ;;
  esac
  shift
done

if ${all_arch}; then
  arch_list=("${CI_PLATFORMS[@]}")
fi

# Stages in the order they run
stages=(c-build c-test rust-build rust-test golden-c golden-rust cargo-test)
for p in "${arch_list[@]}"; do
  stages+=("arch-${p//\//-}")
done
if ${all_arch}; then
  stages+=(arch-linux-amd64-clang)
fi
if [[ -n "${only}" ]]; then
  [[ " ${stages[*]} " == *" ${only} "* ]] \
    || die "Unknown or unselected stage ${only} (stages: ${stages[*]}; arch stages need --arch)"
fi

skip_pytest=""
if ${quick}; then
  skip_pytest="1"
fi

# Run test/docker-test.sh with the environment of the wrapper cleared. The
# arguments are optional VAR=value settings, then the command.
dockertest() {
  env -u IMAGE -u PLATFORM -u BUILD_OPTS -u RUST -u CACHE_VOLUME -u FTL_BIN \
    -u OUT_DIR -u LOG_DIR -u SKIP_PYTEST -u GDB -u BATS_ARGS "$@"
}

c_build() {
  rm -f "${OUT_ROOT}/c/pihole-FTL" "${OUT_ROOT}/c"/*_regression
  dockertest OUT_DIR="${OUT_ROOT}/c" CACHE_VOLUME=ftl-cmake-ci "${DT}" build
}

c_test() {
  dockertest FTL_BIN="${OUT_ROOT}/c/pihole-FTL" OUT_DIR="${OUT_ROOT}/c" \
    CACHE_VOLUME=ftl-cmake-ci SKIP_PYTEST="${skip_pytest}" "${DT}" test
}

rust_build() {
  rm -f "${OUT_ROOT}/rust/pihole-FTL" "${OUT_ROOT}/rust"/*_regression
  dockertest OUT_DIR="${OUT_ROOT}/rust" CACHE_VOLUME=ftl-cmake-ci RUST=1 "${DT}" build
}

rust_test() {
  dockertest FTL_BIN="${OUT_ROOT}/rust/pihole-FTL" OUT_DIR="${OUT_ROOT}/rust" \
    CACHE_VOLUME=ftl-cmake-ci RUST=1 SKIP_PYTEST="${skip_pytest}" "${DT}" test
}

# golden_check <build dir>: compare the binary of that build with the goldens
golden_check() {
  dockertest FTL_BIN="$1/pihole-FTL" OUT_DIR="$1" "${DT}" golden --check
}

cargo_test() {
  dockertest "${DT}" cargo-test
}

# arch_stage <platform (empty = native)> <build dir> <BUILD_OPTS>
arch_stage() {
  local platform="$1" out="$2" opts="$3"
  local -a envs=(OUT_DIR="${out}" CACHE_VOLUME=ftl-cmake-ci RUST=1 BUILD_OPTS="${opts}")
  if [[ -n "${platform}" ]]; then
    envs+=(PLATFORM="${platform}")
  fi
  rm -f "${out}/pihole-FTL" "${out}"/*_regression
  dockertest "${envs[@]}" "${DT}" build
  dockertest "${envs[@]}" "${DT}" run ./pihole-FTL rust-version
  dockertest "${envs[@]}" "${DT}" run bash test/arch_test.sh
}

failed_stages=""
summary_names=()
summary_results=()
summary_times=()

fmt_time() {
  printf '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 ))
}

# run_stage <name> <needs (stage name or -)> <function> [args...]
# Runs the function with errexit, logging to build-ci/logs/<name>.log. A stage
# whose <needs> failed is skipped.
run_stage() {
  local name="$1" needs="$2" log rc start dur result
  shift 2
  log="${LOG_ROOT}/${name}.log"
  if [[ "${needs}" != "-" && " ${failed_stages} " == *" ${needs} "* ]]; then
    echo "== ${name}: SKIP (${needs} failed)"
    summary_names+=("${name}")
    summary_results+=(SKIP)
    summary_times+=(-)
    return 0
  fi
  echo "== ${name}: running, log: ${log}"
  start=${SECONDS}
  set +e
  ( set -e; "$@" ) < /dev/null > "${log}" 2>&1
  rc=$?
  set -e
  dur=$(( SECONDS - start ))
  if [[ ${rc} -eq 0 ]]; then
    result=PASS
  else
    result=FAIL
    failed_stages+=" ${name}"
  fi
  summary_names+=("${name}")
  summary_results+=("${result}")
  summary_times+=("$(fmt_time "${dur}")")
  echo "== ${name}: ${result} after $(fmt_time "${dur}")"
  if [[ ${rc} -ne 0 ]]; then
    echo "   last lines of ${log}:"
    tail -n 15 "${log}" | sed 's/^/   | /'
  fi
}

want() {
  [[ -z "${only}" || "${only}" == "$1" ]]
}

start_total=${SECONDS}
mkdir -p "${LOG_ROOT}"
cd "${REPO}"

if want c-build; then run_stage c-build - c_build; fi
if want c-test; then run_stage c-test c-build c_test; fi
if want rust-build; then run_stage rust-build - rust_build; fi
if want rust-test; then run_stage rust-test rust-build rust_test; fi
if want golden-c; then run_stage golden-c c-build golden_check "${OUT_ROOT}/c"; fi
if want golden-rust; then run_stage golden-rust rust-build golden_check "${OUT_ROOT}/rust"; fi
if want cargo-test; then run_stage cargo-test - cargo_test; fi

for p in "${arch_list[@]}"; do
  name="arch-${p//\//-}"
  if want "${name}"; then
    run_stage "${name}" - arch_stage "${p}" "${OUT_ROOT}/rust-${p//\//-}" ""
  fi
done
if ${all_arch} && want arch-linux-amd64-clang; then
  run_stage arch-linux-amd64-clang - arch_stage "" "${OUT_ROOT}/rust-linux-amd64-clang" clang
fi

echo
printf '%-26s %-6s %s\n' STAGE RESULT DURATION
for i in "${!summary_names[@]}"; do
  printf '%-26s %-6s %s\n' "${summary_names[i]}" "${summary_results[i]}" "${summary_times[i]}"
done
echo "Total: $(fmt_time $(( SECONDS - start_total )))"

if [[ -n "${failed_stages}" ]]; then
  echo "Failed:${failed_stages}"
  exit 1
fi
echo "All stages passed."
