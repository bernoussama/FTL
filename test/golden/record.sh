#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Golden-output recorder and per-module CLI harness
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# Runs the cases of one or more modules against a pihole-FTL binary and either
# stores the normalized results as golden files (record mode, the default) or
# compares the results with the stored golden files (--check).
#
# Usage: test/golden/record.sh [--check] [module...]
#        (no module = all modules in test/golden/cases/)
#
# Run it through test/docker-test.sh golden [--check] [module...], which records
# with the C build by default and can check another binary through FTL_BIN.
# The cases only use CLI subcommands and need no running FTL, so this also works
# as a standalone harness for those modules.
#
# Environment:
#   FTL         Binary under test (default: ./pihole-FTL)
#   GOLDEN_DIR  Where golden files live (default: test/golden/expected)
#
# Case files (test/golden/cases/<module>.cases), one case per line:
#   <name> | <shell command>
# Empty lines and lines starting with # are ignored. The command runs with bash
# in a fresh copy of test/golden/fixtures/; $FTL is the binary under test and
# gzip_header FILE prints a gzip header without its mtime. Each case records
# exit code, stdout and stderr.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FTL="$(realpath "${FTL:-./pihole-FTL}")"
GOLDEN_DIR="${GOLDEN_DIR:-${HERE}/expected}"
check=false
if [[ "${1:-}" == "--check" ]]; then
  check=true
  shift
fi

if [[ ! -x "${FTL}" ]]; then
  echo "No pihole-FTL binary at ${FTL}" >&2
  exit 1
fi

modules=("$@")
if [[ ${#modules[@]} -eq 0 ]]; then
  for f in "${HERE}"/cases/*.cases; do
    modules+=("$(basename "${f}" .cases)")
  done
fi

# Strip what changes between runs or builds: timestamps, PIDs/thread IDs, the
# scratch directory and source locations "(/path/src/file.c:123)". The gzip mtime is left out by gzip_header below.
normalize() {
  sed -E \
    -e "s#${workdir}#<WORKDIR>#g" \
    -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?( [A-Z]{2,5})?/<TIMESTAMP>/g' \
    -e 's/\[[0-9]+[MT]?(\/[TF]?[0-9]+)?\]/[<PID>]/g' \
    -e 's/(PID|pid) [0-9]+/\1 <PID>/g' \
    -e 's#\(/[^()]*/(src/[^():]+):[0-9]+\)#(\1:<LINE>)#g'
}

# Print the fixed gzip header fields (RFC 1952) except MTIME (bytes 4-7)
gzip_header() {
  local hex
  hex="$(od -An -tx1 -N10 -v "$1" | tr -s ' \n' ' ' | sed 's/^ //;s/ $//')"
  read -r id1 id2 cm flg _ _ _ _ xfl os <<< "${hex}"
  echo "gzip header: id=${id1}${id2} cm=${cm} flg=${flg} mtime=<stripped> xfl=${xfl} os=${os}"
}
export -f gzip_header

run_case() {
  local cmd="$1" out err rc
  out="$(mktemp)"
  err="$(mktemp)"
  (cd "${workdir}" && FTL="${FTL}" bash -c "${cmd}" > "${out}" 2> "${err}" < /dev/null)
  rc=$?
  printf '## command: %s\n## exit: %d\n## stdout\n' "${cmd}" "${rc}"
  normalize < "${out}"
  printf '## stderr\n'
  normalize < "${err}"
  rm -f "${out}" "${err}"
}

total=0
failed=0
for module in "${modules[@]}"; do
  cases="${HERE}/cases/${module}.cases"
  if [[ ! -f "${cases}" ]]; then
    echo "Unknown module ${module} (no ${cases})" >&2
    exit 1
  fi
  mkdir -p "${GOLDEN_DIR}/${module}"
  while IFS= read -r line || [[ -n "${line}" ]]; do
    [[ -z "${line//[[:space:]]/}" || "${line}" =~ ^[[:space:]]*# ]] && continue
    name="$(sed -E 's/^[[:space:]]*([^|]*[^|[:space:]])[[:space:]]*\|.*$/\1/' <<< "${line}")"
    cmd="$(sed -E 's/^[^|]*\|[[:space:]]*//' <<< "${line}")"
    if [[ ! "${name}" =~ ^[A-Za-z0-9._-]+$ ]]; then
      echo "Bad case name '${name}' in ${cases}" >&2
      exit 1
    fi
    workdir="$(mktemp -d)"
    cp -r "${HERE}/fixtures/." "${workdir}/"
    result="$(run_case "${cmd}")"
    rm -rf "${workdir}"
    golden="${GOLDEN_DIR}/${module}/${name}.out"
    total=$((total + 1))
    if ${check}; then
      if [[ ! -f "${golden}" ]]; then
        echo "MISSING ${module}/${name}"
        failed=$((failed + 1))
      elif ! diff -u --label "golden/${module}/${name}" --label "actual" "${golden}" - <<< "${result}"; then
        echo "DIFF    ${module}/${name}"
        failed=$((failed + 1))
      else
        echo "ok      ${module}/${name}"
      fi
    else
      printf '%s\n' "${result}" > "${golden}"
      echo "recorded ${module}/${name}"
    fi
  done < "${cases}"
done

if ${check}; then
  echo "${total} cases, ${failed} differ"
  [[ ${failed} -eq 0 ]]
else
  echo "${total} cases recorded in ${GOLDEN_DIR}"
fi
