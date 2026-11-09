#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helpers for the database module. Sourced by the other scripts in this
# directory. They run pihole-FTL against /etc/pihole and /var/log/pihole, so
# they only work inside docker.

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }

DB=/etc/pihole/pihole-FTL.db
GDB=/etc/pihole/gravity.db
LOG=/var/log/pihole/FTL.log
# The suite's own fixtures (run.sh loads the same files)
SUITE=/app/test
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FTL_PID=""

cleanup() {
	if [ -n "${FTL_PID}" ]; then
		kill -TERM "${FTL_PID}" 2>/dev/null
		wait "${FTL_PID}" 2>/dev/null
	fi
	rm -rf /etc/pihole /run/pihole /var/log/pihole
}
trap cleanup EXIT

# Empty the state directories the way run.sh does before FTL starts
reset_state() {
	rm -rf /etc/pihole /run/pihole /var/log/pihole
	mkdir -p /etc/pihole /run/pihole /var/log/pihole
	touch /var/log/pihole/FTL.log /var/log/pihole/pihole.log
}

# Start pihole-FTL in the foreground mode in the background, and wait until it
# has logged the outcome of the database start-up (or until it exits)
start_ftl() {
	"${FTL}" -f > ftl-stdout.txt 2>&1 &
	FTL_PID=$!
	for _ in $(seq 1 300); do
		grep -qE 'Database successfully initialized|Database not available|Expected query database version' "${LOG}" 2>/dev/null && return 0
		kill -0 "${FTL_PID}" 2>/dev/null || return 1
		sleep 0.1
	done
	return 1
}

# Stop pihole-FTL with SIGTERM (its normal shutdown) and print its exit code
stop_ftl() {
	kill -TERM "${FTL_PID}" 2>/dev/null
	wait "${FTL_PID}"
	echo "pihole-FTL exit code after SIGTERM: $?"
	FTL_PID=""
}

# A new database created by FTL itself: empty state, start, stop
create_fresh() {
	reset_state
	start_ftl
	stop_ftl
}

# One line per schema object, sorted by type and name, statement on one line
schema_of() {
	"${FTL}" sqlite3 "$1" "SELECT type || ' ' || name || ': ' || replace(ifnull(sql, '<no sql>'), char(10), ' ') FROM sqlite_master ORDER BY type, name;"
}

dump_schema() {
	schema_of "${DB}"
}

# The ftl table. The creation time (row 2) is the only value that changes
# between runs
dump_ftl() {
	"${FTL}" sqlite3 "${DB}" "SELECT id || '|' || value || '|' || ifnull(description, '') FROM ftl ORDER BY id;" | sed -E 's/^2\|[0-9]+\|/2|<UNIX>|/'
}

# Number of lines in FTL.log so far, to show only what a later run writes
log_mark() {
	wc -l < "${LOG}"
}

# The database lines of FTL.log after line $1 (default: all): start-up, versions,
# upgrades and failures. The shutdown sender details (PID and command line) and
# the gravity and regex warnings from a missing gravity.db are left out, and so is
# the host load warning ("Long-term load"), which depends on the machine
db_log() {
	tail -n +"$(( ${1:-0} + 1 ))" "${LOG}" | grep -E ' (INFO|WARNING|ERROR|CRIT): ' | grep -iE 'database|long-term' | grep -viE 'gravity|regex entries|Asked to terminate|Terminated by|Long-term load'
}
