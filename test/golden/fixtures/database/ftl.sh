#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the database module: runs "$FTL" with the given arguments
# and normalizes what changes between builds: the SQLite version and compiler
# lines of ".version" and the FTL version in the interactive banner. Exit code
# and the other output are kept.
#
# Usage: ftl.sh <arguments of pihole-FTL>

out="$(mktemp)"
err="$(mktemp)"
"${FTL}" "$@" > "${out}" 2> "${err}"
rc=$?
normalize() {
	sed -E \
		-e "s#${FTL}#pihole-FTL#g" \
		-e 's/^SQLite [0-9][0-9.]* .*/SQLite <VERSION>/' \
		-e 's/^SQLite version [0-9][0-9.]* .*/SQLite version <VERSION>/' \
		-e 's/^gcc-.*/<COMPILER>/' \
		-e 's/Pi-hole FTL v[^ ]*/Pi-hole FTL <VERSION>/'
}
normalize < "${out}"
normalize < "${err}" >&2
rm -f "${out}" "${err}"
exit "${rc}"
