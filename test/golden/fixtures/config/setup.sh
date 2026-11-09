#!/bin/bash
# Pi-hole: A black hole for Internet advertisements
# (c) 2026 Pi-hole, LLC (https://pi-hole.net)
# Network-wide ad blocking via your own hardware.
#
# FTL Engine
# Sets up the /etc/pihole state of one config golden case, replacing whatever
# the previous case left. Refuses to run outside docker.
#
# This file is copyright under the latest version of the EUPL.
# Please see LICENSE file for your rights under this license.
#
# Usage: setup.sh STATE
#   none              no /etc/pihole at all
#   nofile            /etc/pihole without pihole.toml
#   template          pihole.toml from test/pihole.toml
#   readonly          template with misc.readOnly = true
#   malformed         template with the [dns] header broken
#   malformed-backup  broken pihole.toml and a valid pihole.toml.1 (port 5353)
#   unknown-keys      template with an unknown key in [dns] and an unknown section
#   wrong-type        template with dns.port given as a string
#   setupvars         setupVars.conf and no pihole.toml
#
# The state of pihole.toml before the case runs is kept in
# /tmp/config-golden-input.toml, which show.sh diff compares against.

[ -f /.dockerenv ] || { echo "refusing: only inside docker" >&2; exit 2; }
# Cases run one after another in the same container: drop what the previous
# case left behind (like reset_state in fixtures/teleporter/lib.sh)
rm -rf /etc/pihole /etc/dnsmasq.d /tmp/config-golden-input.toml

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
state="${1:?usage: setup.sh STATE}"

# run.sh creates the pihole user; without it FTL warns about chown
id pihole > /dev/null 2>&1 || { addgroup -S pihole && adduser -S -D -H -G pihole pihole; } > /dev/null 2>&1

if [[ "${state}" != none ]]; then
	mkdir -p /etc/pihole/config_backups
	case "${state}" in
		nofile) ;;
		template) cp "${HERE}/pihole.toml" /etc/pihole/pihole.toml ;;
		readonly) sed -E 's/^( *)readOnly = false/\1readOnly = true/' "${HERE}/pihole.toml" > /etc/pihole/pihole.toml ;;
		malformed) sed '6s/.*/[dns/' "${HERE}/pihole.toml" > /etc/pihole/pihole.toml ;;
		malformed-backup)
			sed '6s/.*/[dns/' "${HERE}/pihole.toml" > /etc/pihole/pihole.toml
			sed -E 's/^( *)port = 53$/\1port = 5353/' "${HERE}/pihole.toml" > /etc/pihole/config_backups/pihole.toml.1
			;;
		unknown-keys)
			sed -e '6a\  bogusKey = "x"' "${HERE}/pihole.toml" > /etc/pihole/pihole.toml
			printf '\n[bogus]\n  key = "x"\n' >> /etc/pihole/pihole.toml
			;;
		wrong-type) sed -E 's/^( *)port = 53$/\1port = "abc"/' "${HERE}/pihole.toml" > /etc/pihole/pihole.toml ;;
		setupvars)
			printf 'PIHOLE_DNS_1=1.1.1.1\nPIHOLE_DNS_2=8.8.8.8\nWEBPORT=8080\nDNSMASQ_LISTENING=all\n' > /etc/pihole/setupVars.conf
			;;
		*) echo "unknown state: ${state}" >&2; exit 2 ;;
	esac
fi

if [[ -f /etc/pihole/pihole.toml ]]; then
	cp /etc/pihole/pihole.toml /tmp/config-golden-input.toml
else
	: > /tmp/config-golden-input.toml
fi
