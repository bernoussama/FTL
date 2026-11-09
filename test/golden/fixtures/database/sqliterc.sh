#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
#
# FTL Engine
# Golden helper for the database module: runs the sqlite3 shell with a
# ~/.sqliterc that changes the output mode. "-ni" must ignore that file.
#
# Usage: sqliterc.sh <arguments of pihole-FTL sqlite3>

here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p home
printf '.headers on\n.mode column\n' > home/.sqliterc
HOME="$(pwd)/home" "${here}/ftl.sh" "$@"
