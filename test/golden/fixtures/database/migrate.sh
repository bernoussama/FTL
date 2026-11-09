#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the database module: upgrades of an old pihole-FTL.db by
# pihole-FTL on start-up.
#
# Usage: migrate.sh v1|suite schema|ftl|rows|log|compare
#   v1     the oldest database FTL can start from (v1.sql, version 1)
#   suite  the suite's own pre-upgrade fixture (test/pihole-FTL.db.sql, version 9)
# Inside docker only.

. "$(dirname "$0")/common.sh"

kind="$1"
action="$2"

# Write the old database to /etc/pihole/pihole-FTL.db
prepare() {
	reset_state
	case "${kind}" in
		v1) "${FTL}" sqlite3 "${DB}" < "${HERE}/v1.sql" ;;
		suite) "${FTL}" sqlite3 "${DB}" < "${SUITE}/pihole-FTL.db.sql" ;;
		*) echo "usage: migrate.sh v1|suite schema|ftl|rows|log" >&2; exit 2 ;;
	esac
}

# Start FTL on the old database and stop it again, so that the upgrade is done
upgrade() {
	prepare
	start_ftl
	stop_ftl
}

case "${action}" in
	schema)
		upgrade
		dump_schema
		;;
	ftl)
		upgrade
		dump_ftl
		;;
	rows)
		upgrade
		"${FTL}" sqlite3 "${DB}" "SELECT id, timestamp, type, status, domain, client, ifnull(forward, '<null>') FROM queries ORDER BY id;"
		;;
	log)
		upgrade
		db_log
		;;
	compare)
		create_fresh
		dump_schema > fresh.txt
		upgrade
		dump_schema > migrated.txt
		if diff -u fresh.txt migrated.txt; then
			echo "migrated schema identical to a fresh one"
		else
			echo "migrated schema differs from a fresh one (above)"
		fi
		;;
	*)
		echo "usage: migrate.sh v1|suite schema|ftl|rows|log" >&2
		exit 2
		;;
esac
