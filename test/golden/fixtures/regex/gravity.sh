#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the regex module: prepares /etc/pihole/gravity.db for the
# database mode of "regex-test <domain>" (no regex argument).
#
# Usage: gravity.sh base|empty-row|bad-row|missing
#   base       the suite's gravity.db.sql (regex rows 6 to 16 and 3 to 4)
#   empty-row  base plus an empty deny regex row (must be skipped)
#   bad-row    base plus a deny regex row that does not compile
#   missing    no gravity.db at all
# Inside docker only. rt.sh removes /etc/pihole when the case ends.

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }

SUITE=/app/test
rm -rf /etc/pihole
[ "$1" = missing ] && exit 0
mkdir -p /etc/pihole
"${FTL}" sqlite3 /etc/pihole/gravity.db < "${SUITE}/gravity.db.sql" || exit 1
case "$1" in
	empty-row) "${FTL}" sqlite3 /etc/pihole/gravity.db "INSERT INTO domainlist (type, domain) VALUES (3, '');" ;;
	bad-row) "${FTL}" sqlite3 /etc/pihole/gravity.db "INSERT INTO domainlist (type, domain) VALUES (3, 'f{x}');" ;;
esac
