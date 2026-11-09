#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Shared functions of the teleporter golden cases, sourced by export.sh and
# import.sh. They replace /etc/pihole and /etc/dnsmasq.d, so they only run in
# the test container.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FTL="${FTL:?FTL must point to the binary under test}"

# Remove the Pi-hole state (before and after every case)
reset_state() {
	rm -rf /etc/pihole /etc/dnsmasq.d
}

# Recreate the state that run.sh sets up, without its destructive parts: the
# configuration, gravity and FTL databases, the DHCP leases and dnsmasq.d
setup_state() {
	# run.sh creates the pihole user; without it FTL warns about chown
	id pihole > /dev/null 2>&1 || { addgroup -S pihole && adduser -S -D -H -G pihole pihole; } > /dev/null 2>&1
	reset_state
	mkdir -p /etc/pihole /etc/dnsmasq.d
	cp "${HERE}/pihole.toml" /etc/pihole/pihole.toml
	"${FTL}" sqlite3 /etc/pihole/gravity.db < "${HERE}/gravity.db.sql"
	"${FTL}" sqlite3 /etc/pihole/pihole-FTL.db < "${HERE}/pihole-FTL.db.sql"
	cp "${HERE}/dhcp.leases" /etc/pihole/dhcp.leases
	cp "${HERE}"/dnsmasq/*.conf /etc/dnsmasq.d/
}

# Hides what changes from run to run in an output: the host part and the time
# of an archive name, and the order of the "Skipping" lines of dnsmasq.d files
# (they are archived in readdir() order, which depends on the filesystem)
norm() {
	sed -E 's/pi-hole_[^_ ]+_teleporter_[0-9]{4}(-[0-9]{2}){2}_[0-9]{2}(-[0-9]{2}){2}_[A-Za-z]+\.zip/pi-hole_<HOST>_teleporter_<DATE>.zip/g' |
	awk '
		function flush(   i) {
			if (n == 0) return
			for (i = 1; i <= n; i++) print buf[i] | "sort"
			close("sort")
			n = 0
		}
		/^Skipping file etc\/dnsmasq\.d\// { buf[++n] = $0; next }
		{ flush(); print }
		END { flush() }'
}

# Run the binary under test. Its stdout and stderr are printed (normalized) to
# our stdout and stderr, and its exit code is returned.
run_ftl() {
	local out err rc
	out="$(mktemp)"
	err="$(mktemp)"
	"${FTL}" "$@" > "${out}" 2> "${err}" < /dev/null
	rc=$?
	norm < "${out}"
	norm < "${err}" >&2
	rm -f "${out}" "${err}"
	return "${rc}"
}

# Full SQL dump of a SQLite file, as stored (used to compare two states of the
# same run; the schema defaults use now(), so the values differ between runs)
dump_db() {
	"${FTL}" sqlite3 "$1" .dump
}

# The same dump with 10-digit numbers (epoch timestamps) masked, for output
show_db() {
	dump_db "$1" | sed -E 's/\b1[0-9]{9}\b/<EPOCH>/g'
}

# Export the state into export.zip. The exit code is returned.
export_zip() {
	local rc
	run_ftl --teleporter > /dev/null 2>&1
	rc=$?
	mv pi-hole_*_teleporter_*.zip export.zip 2> /dev/null
	return "${rc}"
}

# One line per archive entry (name, method, size, comment) and the CRC check,
# sorted, because the order of the dnsmasq.d entries follows readdir(). The
# sizes of the SQLite databases and of /etc/hosts are masked: they depend on
# the SQLite build and on the container.
list_zip() {
	python3 -I "${HERE}/zip.py" list "$1" | sort | awk -F'\t' 'BEGIN { OFS = "\t" }
		$1 ~ /\.db$/ || $1 == "etc/hosts" { $3 = "<size>" }
		{ print }'
}

# Everything under /etc/pihole and /etc/dnsmasq.d (including config_backups/)
# with a hash of each file's content. A SQLite file is hashed through its
# dump: copying or importing into it changes the bytes, not the content. A text
# file is hashed without its comment lines, which carry the build's version and
# branch and the time of the write.
tree() {
	local f
	find /etc/pihole /etc/dnsmasq.d -mindepth 1 2> /dev/null | sort | while IFS= read -r f; do
		if [ -d "${f}" ]; then
			echo "${f}/ directory"
		elif [ "$(head -c 15 "${f}")" = "SQLite format 3" ]; then
			echo "${f} sqlite-dump $(show_db "${f}" | sha256sum | cut -c1-16)"
		else
			echo "${f} $(grep -v '^#' "${f}" | sha256sum | cut -c1-16)"
		fi
	done
}

# Print what the tree looks like now and what changed since $1 (a tree listing)
changes_since() {
	tree > after.tree
	if diff "$1" after.tree > /dev/null; then
		echo "tree: no file in /etc/pihole or /etc/dnsmasq.d changed"
	else
		echo "tree: changes (- before, + after)"
		diff "$1" after.tree
	fi
}
