#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the regex module: runs "$FTL" with the given arguments and
# normalizes the timing lines, the only part of regex-test output that changes
# between runs. Stdout, stderr and the exit code of pihole-FTL are kept.
#
# Usage: rt.sh [-q] regex-test <domain> [<regex>]
# Inside docker only: the database mode reads /etc/pihole/gravity.db, which this
# script removes on exit (gravity.sh prepares it for each case).

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }
trap 'rm -rf /etc/pihole' EXIT

out="$(mktemp)"
err="$(mktemp)"
"${FTL}" "$@" > "${out}" 2> "${err}"
rc=$?
# Usage lines print argv[0], which is the binary's path in the container
normalize() {
	sed -E -e "s#${FTL}#pihole-FTL#g" -e 's/[0-9]+\.[0-9]+ msec/<MSEC>/'
}
normalize < "${out}"
normalize < "${err}" >&2
rm -f "${out}" "${err}"
exit "${rc}"
