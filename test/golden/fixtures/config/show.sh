#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Shows the /etc/pihole state after a config golden case: the files, the
# changes against the state before the case, a grep of pihole.toml, the
# backups and the body of pihole.toml. The version and the password hashes
# are masked, as in ftl.sh.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# Usage: show.sh state | diff | grep PATTERN | backups | body

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF=/etc/pihole/pihole.toml
INPUT=/tmp/config-golden-input.toml

mask() {
	sed -E \
		-e 's/^(# Pi-hole configuration file ).*/\1(<VERSION>)/' \
		-e 's/(\$BALLOON-SHA256\$v=[0-9]+\$)[^ "]*/\1<HASH>/g'
}

# The dns.port line, which is in the [dns] section
port_of() {
	awk '/^\[/ { section = $0 } section == "[dns]" && /^ *port = / { sub(/^ */, ""); print; exit }' "$1"
}

case "${1:?usage: show.sh state|diff|grep PATTERN|backups|body}" in
	state)
		echo "/etc/pihole:"
		ls -1A /etc/pihole | grep -v '\.lock$'
		echo "config_backups: $(ls -1A /etc/pihole/config_backups | wc -l | tr -d ' ') entries"
		;;
	diff)
		[[ -f "${CONF}" ]] || { echo "no pihole.toml"; exit 0; }
		changes="$(diff <(mask < "${INPUT}") <(mask < "${CONF}") | sed -E "/^(---|\+\+\+) \/dev\/fd\//d")"
		if [[ -n "${changes}" ]]; then echo "${changes}"; else echo "no difference"; fi
		;;
	grep)
		mask < "${CONF}" | grep -E -n -- "${2:?usage: show.sh grep PATTERN}" || echo "no match: ${2}"
		;;
	backups)
		for i in $(seq 1 16); do
			f="/etc/pihole/config_backups/pihole.toml.${i}"
			if [[ -f "${f}" ]]; then
				echo "pihole.toml.${i}: $(port_of "${f}")"
			else
				echo "pihole.toml.${i}: missing"
			fi
		done
		;;
	body)
		changes="$(diff <(tail -n +6 "${HERE}/pihole.toml") <(tail -n +6 "${CONF}") | sed -E "/^(---|\+\+\+) \/dev\/fd\//d")"
		if [[ -n "${changes}" ]]; then echo "${changes}"; else echo "identical from line 6"; fi
		;;
	*)
		echo "unknown subcommand: $1" >&2
		exit 2
		;;
esac
