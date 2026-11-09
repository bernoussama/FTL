#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the database module: pihole-FTL.db files that FTL must not
# use or change. The file hash before and after the start shows that FTL left
# the file alone.
#
# Usage: bad.sh empty|newer|junk   (inside docker only)

. "$(dirname "$0")/common.sh"

# Run FTL once on ${DB} and report whether the file changed
run_on_existing() {
	before="$(sha256sum < "${DB}")"
	mark="$(log_mark)"
	start_ftl
	stop_ftl
	after="$(sha256sum < "${DB}")"
	if [ "${before}" = "${after}" ]; then
		echo "database file unchanged"
	else
		echo "database file changed"
	fi
	db_log "${mark}"
}

case "$1" in
	empty)
		reset_state
		: > "${DB}"
		run_on_existing
		;;
	newer)
		# A database written by a newer FTL (version 23 > 22)
		create_fresh
		"${FTL}" sqlite3 "${DB}" "UPDATE ftl SET value = 23 WHERE id = 0;"
		run_on_existing
		;;
	junk)
		reset_state
		echo 'this is not a SQLite database' > "${DB}"
		run_on_existing
		;;
	*)
		echo "usage: bad.sh empty|newer|junk" >&2
		exit 2
		;;
esac
