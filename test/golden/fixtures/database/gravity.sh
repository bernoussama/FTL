#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the database module: gravity.db as the suite loads it
# (test/gravity.db.sql), the triggers and views in it, and the gravity CLI
# that writes into a gravity database (gravity parseList).
#
# Usage: gravity.sh schema|rows|triggers|checklist|parse   (inside docker only)

. "$(dirname "$0")/common.sh"

# Load the suite's gravity.db.sql into a new /etc/pihole/gravity.db
load_gravity() {
	reset_state
	"${FTL}" sqlite3 "${GDB}" < "${SUITE}/gravity.db.sql"
}

case "$1" in
	schema)
		load_gravity
		schema_of "${GDB}"
		;;
	rows)
		load_gravity
		"${FTL}" sqlite3 "${GDB}" "SELECT 'domainlist', count(*) FROM domainlist UNION ALL SELECT 'adlist', count(*) FROM adlist UNION ALL SELECT 'group', count(*) FROM \"group\" UNION ALL SELECT 'domainlist_by_group', count(*) FROM domainlist_by_group UNION ALL SELECT 'vw_denylist', count(*) FROM vw_denylist UNION ALL SELECT 'vw_allowlist', count(*) FROM vw_allowlist UNION ALL SELECT 'vw_regex_denylist', count(*) FROM vw_regex_denylist UNION ALL SELECT 'vw_regex_allowlist', count(*) FROM vw_regex_allowlist UNION ALL SELECT 'vw_adlist', count(*) FROM vw_adlist;"
		;;
	triggers)
		load_gravity
		echo "-- insert into domainlist adds a default-group link"
		"${FTL}" sqlite3 "${GDB}" "INSERT INTO domainlist (type, domain) VALUES (0, 'trigger.test'); SELECT domainlist_id, group_id FROM domainlist_by_group WHERE domainlist_id = last_insert_rowid();"
		echo "-- deleting group 0 re-creates the Default group"
		"${FTL}" sqlite3 "${GDB}" "DELETE FROM \"group\" WHERE id = 0; SELECT id, name, enabled FROM \"group\" ORDER BY id;"
		;;
	checklist)
		# Entries that are domains are counted, the rest are reported
		"${FTL}" gravity checkList "${HERE}/adlist.txt"
		;;
	parse)
		load_gravity
		"${FTL}" sqlite3 "${GDB}" "DELETE FROM gravity;"
		"${FTL}" gravity parseList "${HERE}/adlist.txt" "${GDB}" 1
		"${FTL}" sqlite3 "${GDB}" "SELECT domain FROM gravity ORDER BY domain;"
		;;
	*)
		echo "usage: gravity.sh schema|rows|triggers|checklist|parse" >&2
		exit 2
		;;
esac
