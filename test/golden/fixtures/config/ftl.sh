#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Runs the binary under test for the config golden cases and prints its output
# with the parts that differ between runs masked: the load warning (it depends
# on the host) and the password hashes (they have a random salt). The exit code
# of the binary is the exit code of this script.
#
# The suite exports these variables (test/run.sh), among others. The template keeps
# nice, shmem and api as env-forced lines, so a write without them would reset
# those lines to their defaults. They are set here unless a case sets them.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# Usage: ftl.sh ARGUMENTS...

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }

export FTLCONF_misc_nice="${FTLCONF_misc_nice:--11}"
export FTLCONF_MISC_CHECK_SHMEM="${FTLCONF_MISC_CHECK_SHMEM:-91}"
export FTLCONF_debug_api="${FTLCONF_debug_api:-not_a_bool}"

mask() {
	sed -E -e '/Long-term load/d' -e 's/(\$BALLOON-SHA256\$v=[0-9]+\$)[^ "]*/\1<HASH>/g'
}

out="$(mktemp)"
err="$(mktemp)"
"${FTL:?FTL must point to the binary under test}" "$@" > "${out}" 2> "${err}" < /dev/null
rc=$?
mask < "${out}"
mask < "${err}" >&2
rm -f "${out}" "${err}"
exit "${rc}"
