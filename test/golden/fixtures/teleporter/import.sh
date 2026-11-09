#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Teleporter import: "pihole-FTL --teleporter FILE" on a known state, with the
# archive built by the case (by FTL's export, or by zip.py for invalid input),
# and what the import changes in /etc/pihole and /etc/dnsmasq.d. The scenarios
# are the import cases of teleporter.cases.
#
# Usage: bash ./teleporter/import.sh SCENARIO
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

. "$(dirname "$0")/lib.sh"
trap reset_state EXIT
setup_state

# Build input.zip from the entries given (zip.py make arguments)
make_zip() {
	python3 -I "${HERE}/zip.py" make input.zip "$@"
}

# Remember the state, run the import of $1 and print what it changed
import_and_compare() {
	tree > before.tree
	run_ftl --teleporter "$1"
	rc=$?
	changes_since before.tree
	return "${rc}"
}

# Print whether a file of the state equals the fixture it started from
same_as_fixture() {
	if cmp -s "$1" "$2"; then
		echo "$1: identical to the fixture it was set up from"
	else
		echo "$1: differs from the fixture it was set up from"
	fi
}

case "$1" in
	roundtrip-gravity)
		export_zip
		echo "export exit: $?"
		dump_db /etc/pihole/gravity.db > gravity.before
		"${FTL}" sqlite3 /etc/pihole/gravity.db \
			"DELETE FROM domainlist; DELETE FROM client; INSERT INTO domainlist (type, domain, enabled, date_added, date_modified) VALUES (0, 'changed.test', 1, 1559928803, 1559928803);"
		sed -i 's/9.9.9.9/1.1.1.1/' /etc/pihole/pihole.toml
		printf 'changed\n' > /etc/pihole/dhcp.leases
		echo "state changed: gravity, pihole.toml, dhcp.leases"
		run_ftl --teleporter export.zip
		rc=$?
		dump_db /etc/pihole/gravity.db > gravity.after
		if cmp -s gravity.before gravity.after; then
			echo "gravity: identical to the exported state"
		else
			echo "gravity: differs from the exported state"
			diff gravity.before gravity.after
		fi
		grep -E '^\s*"[0-9.]+"$' /etc/pihole/pihole.toml
		same_as_fixture /etc/pihole/dhcp.leases "${HERE}/dhcp.leases"
		exit "${rc}"
		;;

	writes)
		# Export first, to see whether it changes the state too
		tree > before-export.tree
		export_zip
		echo "export exit: $?"
		tree > before.tree
		changes_since before-export.tree | sed 's/^tree:/export tree:/'
		run_ftl --teleporter export.zip
		rc=$?
		changes_since before.tree
		exit "${rc}"
		;;

	ftl-db-ignored)
		export_zip
		"${FTL}" sqlite3 /etc/pihole/pihole-FTL.db \
			"INSERT INTO aliasclient (id, name) VALUES (1, 'changed-client');"
		dump_db /etc/pihole/pihole-FTL.db > ftl.before
		run_ftl --teleporter export.zip
		rc=$?
		dump_db /etc/pihole/pihole-FTL.db > ftl.after
		if cmp -s ftl.before ftl.after; then
			echo "pihole-FTL.db: unchanged by the import"
		else
			echo "pihole-FTL.db: changed by the import"
			diff ftl.before ftl.after
		fi
		exit "${rc}"
		;;

	dnsmasq-d-ignored)
		export_zip
		printf 'dhcp-host=00:00:00:00:00:00,192.0.2.99,changed\n' > /etc/dnsmasq.d/04-pihole-static-dhcp.conf
		run_ftl --teleporter export.zip
		rc=$?
		echo "/etc/dnsmasq.d/04-pihole-static-dhcp.conf after the import:"
		cat /etc/dnsmasq.d/04-pihole-static-dhcp.conf
		exit "${rc}"
		;;

	dhcp-valid)
		printf '1893456000 00:11:22:33:44:55 192.0.2.30 printer *\nduid 00:01:00:01:23:45:67:89:ab:cd:ef:01:23:45\n' > new.leases
		make_zip etc/pihole/dhcp.leases=new.leases
		import_and_compare input.zip
		rc=$?
		cmp -s /etc/pihole/dhcp.leases new.leases && echo "dhcp.leases: now the leases of the archive"
		exit "${rc}"
		;;

	dhcp-invalid)
		printf 'not a lease record\n' > bad.leases
		make_zip etc/pihole/dhcp.leases=bad.leases
		import_and_compare input.zip
		exit $?
		;;

	dhcp-empty)
		: > empty.leases
		make_zip etc/pihole/dhcp.leases=empty.leases
		import_and_compare input.zip
		rc=$?
		echo "dhcp.leases size: $(wc -c < /etc/pihole/dhcp.leases) bytes"
		exit "${rc}"
		;;

	no-entries)
		printf 'nothing for the import\n' > readme.txt
		make_zip README.txt=readme.txt
		import_and_compare input.zip
		exit $?
		;;

	traversal)
		printf 'probe\n' > probe.txt
		make_zip '../ftl-traversal-probe=probe.txt' '/ftl-traversal-abs=probe.txt' \
			'etc/pihole/../dhcp.leases=probe.txt' 'ETC/PIHOLE/PIHOLE.TOML=probe.txt'
		import_and_compare input.zip
		rc=$?
		for p in /ftl-traversal-abs /etc/ftl-traversal-probe /tmp/ftl-traversal-probe /etc/dhcp.leases ./etc; do
			[ -e "${p}" ] && echo "created: ${p}" || echo "not created: ${p}"
		done
		exit "${rc}"
		;;

	oversize-declared)
		# The header declares 256 MiB + 1 bytes; the import skips the entry
		make_zip --declare etc/pihole/pihole.toml=268435457 etc/pihole/pihole.toml="${HERE}/pihole.toml"
		import_and_compare input.zip
		exit $?
		;;

	empty-file)
		: > input.zip
		import_and_compare input.zip
		exit $?
		;;

	over-limit)
		head -c 134217729 /dev/zero > input.zip
		import_and_compare input.zip
		exit $?
		;;

	at-limit)
		head -c 134217728 /dev/zero > input.zip
		import_and_compare input.zip
		exit $?
		;;

	random-bytes)
		python3 -I "${HERE}/zip.py" noise 300 7 > input.zip
		import_and_compare input.zip
		exit $?
		;;

	truncated)
		make_zip etc/pihole/pihole.toml="${HERE}/pihole.toml" etc/pihole/dhcp.leases="${HERE}/dhcp.leases"
		mv input.zip full.zip
		size="$(wc -c < full.zip)"
		head -c $((size / 2)) full.zip > input.zip
		import_and_compare input.zip
		exit $?
		;;

	missing-file)
		import_and_compare does-not-exist.zip
		exit $?
		;;

	v5-targz)
		# A Pi-hole v5 backup: tar.gz with pihole-FTL.conf. Only the API imports
		# these; the command line reads ZIP archives only.
		printf 'WEBPORT=80\n' > pihole-FTL.conf
		tar --owner=0 --group=0 --mtime=@0 -cf v5.tar pihole-FTL.conf
		gzip -n -c v5.tar > teleporter.tar.gz
		import_and_compare teleporter.tar.gz
		exit $?
		;;

	invalid-toml)
		printf '[dns\nupstreams = [\n' > bad.toml
		make_zip etc/pihole/pihole.toml=bad.toml
		import_and_compare input.zip
		exit $?
		;;

	empty-toml)
		: > empty.toml
		make_zip etc/pihole/pihole.toml=empty.toml
		import_and_compare input.zip
		exit $?
		;;

	invalid-value)
		# An embedded newline in dns.hostRecord carries a second dnsmasq directive
		sed 's/hostRecord = ""/hostRecord = "pi.hole,127.0.0.1\\nlog-queries"/' "${HERE}/pihole.toml" > bad-value.toml
		echo "input line: $(grep hostRecord bad-value.toml)"
		make_zip etc/pihole/pihole.toml=bad-value.toml
		import_and_compare input.zip
		exit $?
		;;

	gravity-no-header)
		python3 -I "${HERE}/zip.py" noise 200 3 > not-sqlite.db
		make_zip etc/pihole/gravity.db=not-sqlite.db
		import_and_compare input.zip
		exit $?
		;;

	gravity-short)
		# 99 bytes: below the 100-byte database header
		head -c 99 /dev/zero > short.db
		make_zip etc/pihole/gravity.db=short.db
		import_and_compare input.zip
		exit $?
		;;

	gravity-corrupt)
		# Valid header, invalid b-tree page 2
		cp /etc/pihole/gravity.db corrupt.db
		dd if=/dev/zero of=corrupt.db bs=1 seek=4096 count=8 conv=notrunc 2> /dev/null
		make_zip etc/pihole/gravity.db=corrupt.db
		import_and_compare input.zip
		exit $?
		;;

	partial-failure)
		# pihole.toml comes first in the archive and is installed before the
		# invalid gravity.db is reached
		sed 's/9.9.9.9/1.1.1.1/' "${HERE}/pihole.toml" > new.toml
		python3 -I "${HERE}/zip.py" noise 200 3 > not-sqlite.db
		make_zip etc/pihole/pihole.toml=new.toml etc/pihole/gravity.db=not-sqlite.db
		import_and_compare input.zip
		rc=$?
		grep -E '^\s*"[0-9.]+"$' /etc/pihole/pihole.toml
		exit "${rc}"
		;;

	gravity-only)
		# An archive with only gravity.db: only the tables it carries are replaced
		export_zip
		python3 -I "${HERE}/zip.py" extract export.zip etc/pihole/gravity.db archived-gravity.db
		dump_db /etc/pihole/gravity.db > gravity.before
		"${FTL}" sqlite3 /etc/pihole/gravity.db \
			"DELETE FROM domainlist; INSERT INTO domainlist (type, domain, enabled, date_added, date_modified) VALUES (0, 'changed.test', 1, 1559928803, 1559928803);"
		make_zip etc/pihole/gravity.db=archived-gravity.db
		tree > before.tree
		run_ftl --teleporter input.zip
		rc=$?
		dump_db /etc/pihole/gravity.db > gravity.after
		if cmp -s gravity.before gravity.after; then
			echo "gravity: identical to the exported state"
		else
			echo "gravity: differs from the exported state"
			diff gravity.before gravity.after
		fi
		changes_since before.tree
		exit "${rc}"
		;;

	*)
		echo "unknown scenario: $1" >&2
		exit 2
		;;
esac
