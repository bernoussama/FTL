#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the database module: the long-term database that pihole-FTL
# creates when /etc/pihole/pihole-FTL.db does not exist yet.
#
# Usage: fresh.sh schema|ftl|counters|mode|log|reopen   (inside docker only)

. "$(dirname "$0")/common.sh"

case "$1" in
	schema)
		create_fresh
		dump_schema
		;;
	ftl)
		create_fresh
		dump_ftl
		;;
	counters)
		create_fresh
		"${FTL}" sqlite3 "${DB}" "SELECT id, value FROM counters ORDER BY id;"
		;;
	mode)
		create_fresh
		stat -c '%a' "${DB}"
		;;
	log)
		create_fresh
		db_log
		;;
	reopen)
		create_fresh
		dump_schema > before.txt
		upgrades_before="$(grep -c 'Updating long-term' "${LOG}")"
		start_ftl && stop_ftl
		echo "database upgrades on the second start: $(( $(grep -c 'Updating long-term' "${LOG}") - upgrades_before ))"
		if dump_schema | diff -q before.txt - > /dev/null; then
			echo "schema unchanged on the second start"
		else
			echo "schema changed on the second start"
		fi
		;;
	*)
		echo "usage: fresh.sh schema|ftl|counters|mode|log|reopen" >&2
		exit 2
		;;
esac
