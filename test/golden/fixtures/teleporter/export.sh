#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Teleporter export: "pihole-FTL --teleporter" in a known state, and what the
# archive holds. The scenarios are the export cases of teleporter.cases.
#
# Usage: bash ./teleporter/export.sh SCENARIO
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

. "$(dirname "$0")/lib.sh"
trap reset_state EXIT
setup_state

case "$1" in
	name)
		# The archive name is printed last
		run_ftl --teleporter
		rc=$?
		echo "archives in the directory: $(ls pi-hole_*.zip 2> /dev/null | wc -l)"
		exit "${rc}"
		;;

	entries)
		export_zip
		rc=$?
		echo "export exit: ${rc}"
		[ -f export.zip ] && list_zip export.zip
		exit "${rc}"
		;;

	verbatim)
		export_zip
		rc=$?
		echo "export exit: ${rc}"
		for name in etc/pihole/pihole.toml etc/pihole/dhcp.leases \
		            etc/dnsmasq.d/01-pihole.conf etc/dnsmasq.d/04-pihole-static-dhcp.conf \
		            etc/dnsmasq.d/05-pihole-custom-cname.conf etc/hosts; do
			python3 -I "${HERE}/zip.py" extract export.zip "${name}" member
			size="$(wc -c < member)"
			[ "${name}" = etc/hosts ] && size="<size>"
			if cmp -s member "/${name}"; then
				echo "${name}: identical to /${name} (${size} bytes)"
			else
				echo "${name}: differs from /${name} (${size} bytes)"
			fi
		done
		exit "${rc}"
		;;

	gravity)
		export_zip
		rc=$?
		echo "export exit: ${rc}"
		python3 -I "${HERE}/zip.py" extract export.zip etc/pihole/gravity.db member.db
		echo "tables: $("${FTL}" sqlite3 member.db .tables | tr -s ' ' | tr '\n' ' ')"
		show_db member.db | grep '^INSERT'
		exit "${rc}"
		;;

	ftl)
		export_zip
		rc=$?
		echo "export exit: ${rc}"
		python3 -I "${HERE}/zip.py" extract export.zip etc/pihole/pihole-FTL.db member.db
		echo "tables: $("${FTL}" sqlite3 member.db .tables | tr -s ' ' | tr '\n' ' ')"
		show_db member.db | grep '^INSERT'
		exit "${rc}"
		;;

	no-dhcp-leases)
		rm -f /etc/pihole/dhcp.leases
		export_zip
		rc=$?
		echo "export exit: ${rc}"
		[ -f export.zip ] && list_zip export.zip
		exit "${rc}"
		;;

	no-dnsmasq-dir)
		rm -rf /etc/dnsmasq.d
		export_zip
		rc=$?
		echo "export exit: ${rc}"
		[ -f export.zip ] && list_zip export.zip
		exit "${rc}"
		;;

	missing-toml)
		rm -f /etc/pihole/pihole.toml
		run_ftl --teleporter
		rc=$?
		echo "archives in the directory: $(ls pi-hole_*.zip 2> /dev/null | wc -l)"
		echo "/etc/pihole after the export:"
		ls /etc/pihole
		exit "${rc}"
		;;

	missing-gravity)
		rm -f /etc/pihole/gravity.db
		run_ftl --teleporter
		rc=$?
		echo "archives in the directory: $(ls pi-hole_*.zip 2> /dev/null | wc -l)"
		echo "/etc/pihole after the export:"
		ls /etc/pihole
		if [ -f /etc/pihole/gravity.db ]; then
			echo "gravity.db size: $(wc -c < /etc/pihole/gravity.db)"
		else
			echo "gravity.db: not created"
		fi
		exit "${rc}"
		;;

	corrupt-ftl)
		printf 'this is not a SQLite database\n' > /etc/pihole/pihole-FTL.db
		run_ftl --teleporter
		rc=$?
		echo "archives in the directory: $(ls pi-hole_*.zip 2> /dev/null | wc -l)"
		exit "${rc}"
		;;

	corrupt-gravity)
		printf 'this is not a SQLite database\n' > /etc/pihole/gravity.db
		run_ftl --teleporter
		rc=$?
		echo "archives in the directory: $(ls pi-hole_*.zip 2> /dev/null | wc -l)"
		exit "${rc}"
		;;

	extra-args)
		run_ftl --teleporter export.zip extra
		rc=$?
		echo "archives in the directory: $(ls pi-hole_*.zip 2> /dev/null | wc -l)"
		exit "${rc}"
		;;

	*)
		echo "unknown scenario: $1" >&2
		exit 2
		;;
esac
