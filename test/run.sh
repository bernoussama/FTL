#!/bin/bash

# WARNING: This script is meant to run inside a disposable container (see
# test/docker-test.sh). It kills running pihole-FTL processes, deletes
# /etc/pihole, /etc/dnsmasq.d and /var/log/pihole, creates a pihole user and
# sets file capabilities.
#
# Environment variables:
#   FTL_BIN      Binary under test (default: ./pihole-FTL). The tests call
#                ./pihole-FTL and check argv[0] in some outputs, so a different
#                binary is copied to ./pihole-FTL before the tests run.
#   BATS_ARGS    Extra arguments for both bats runs, shell-quoted, e.g.
#                "--filter-tags contract" or "--filter 'Regex Test'".
#   SKIP_PYTEST  Set to 1 to skip the pytest API tests.
#   NO_UPLOAD    Set to 1 to not upload logs to tricorder.pi-hole.net on
#                failure. LOG_DIR (if set) receives copies of the logs instead.

# Skip tests on targets not supporting them
if [[ ${TEST} == "false" ]]; then
  echo "Skipping tests (CI_ARCH: ${CI_ARCH})!"
  exit 0
fi

# Parse extra bats arguments (shell-quoted string -> array)
bats_args=()
if [[ -n "${BATS_ARGS}" ]]; then
  eval "bats_args=(${BATS_ARGS})"
fi

# Stage the binary under test as ./pihole-FTL
FTL_BIN="${FTL_BIN:-./pihole-FTL}"
if [[ ! -x "${FTL_BIN}" ]]; then
  echo "FTL binary ${FTL_BIN} does not exist or is not executable"
  exit 1
fi
if [[ "$(realpath "${FTL_BIN}")" != "$(realpath -m ./pihole-FTL)" ]]; then
  echo "Testing ${FTL_BIN} (copied to ./pihole-FTL)"
  cp -f "${FTL_BIN}" ./pihole-FTL
fi

# Create pihole user if it does not exist
if ! id -u pihole &> /dev/null; then
  useradd -m -s /usr/sbin/nologin pihole
fi

# Kill possibly running pihole-FTL process
while pidof -s pihole-FTL > /dev/null; do
  pid="$(pidof -s pihole-FTL)"
  echo "Terminating running pihole-FTL process with PID ${pid}"
  kill "$pid"
  sleep 1
done

# Clean up possible old files from earlier test runs
rm -rf /etc/pihole /etc/dnsmasq.d /var/log/pihole /dev/shm/FTL-*
rm -f /tmp/dnsmasq_warnings /tmp/ftl_test_*.json

# Create necessary directories and files
mkdir -p /home/pihole /etc/pihole /run/pihole /var/log/pihole /etc/pihole/config_backups /var/www/html
echo "" > /var/log/pihole/FTL.log
echo "" > /var/log/pihole/pihole.log
echo "" > /var/log/pihole/webserver.log
touch /run/pihole-FTL.pid ptr.log
touch /etc/pihole/dhcp.leases
chown -R pihole:pihole /etc/pihole /run/pihole /var/log/pihole
chown pihole:pihole /run/pihole-FTL.pid

# Copy binary into a location the new user pihole can access
cp ./pihole-FTL /home/pihole/pihole-FTL
chmod +x /home/pihole/pihole-FTL
# Note: We cannot add CAP_NET_RAW and CAP_NET_ADMIN at this point
setcap CAP_NET_BIND_SERVICE+eip /home/pihole/pihole-FTL

# Prepare gravity database
./pihole-FTL sqlite3 /etc/pihole/gravity.db < test/gravity.db.sql
chown pihole:pihole /etc/pihole/gravity.db

# Prepare pihole-FTL database
rm -rf /etc/pihole/pihole-FTL.db
./pihole-FTL sqlite3 /etc/pihole/pihole-FTL.db < test/pihole-FTL.db.sql
chown pihole:pihole /etc/pihole/pihole-FTL.db

# Prepare TLS key and certificate
cp test/test.pem /etc/pihole/test.pem
cp test/test.crt /etc/pihole/test.crt

# Prepare pihole.toml
cp test/pihole.toml /etc/pihole/pihole.toml
chown pihole:pihole /etc/pihole/pihole.toml

# Leave a world-readable CLI password file behind, as an interrupted shutdown
# can, and keep it open like a local reader could. FTL has to replace it rather
# than write the new password into it
printf 'stale\n' > /etc/pihole/cli_pw
chmod 0666 /etc/pihole/cli_pw
chown pihole:pihole /etc/pihole/cli_pw
sleep 600 < /etc/pihole/cli_pw > /dev/null 2>&1 &
echo $! > /tmp/cli_pw_holder.pid

# Prepare 01-pihole-tests.conf
mkdir -p /etc/dnsmasq.d
cp test/01-pihole-tests.conf /etc/dnsmasq.d/01-pihole-tests.conf

# Prepare versions file (read by /api/version)
cp test/versions /etc/pihole/versions

# Prepare Lua test script
cp test/broken_lua.lp /var/www/html/broken_lua.lp
cp test/broken_lua_2.lp /var/www/html/broken_lua_2.lp

# Prepare local powerDNS resolver
if ! bash test/pdns/setup.sh; then
  echo "Local PowerDNS setup failed, the DNS tests below cannot pass"
  exit 1
fi

# Set restrictive umask
OLDUMASK=$(umask)
umask 0022

# Set exemplary config value by environment variable
export FTLCONF_misc_nice="-11"
export FTLCONF_dns_upstrrr="-11"
export FTLCONF_debug_api="not_a_bool"
export FTLCONF_MISC_CHECK_SHMEM=91
export FTLCONF_files_pcap=$'\001./test/pcap'

# Start FTL
if ! su pihole -s /bin/sh -c /home/pihole/pihole-FTL; then
  echo "pihole-FTL failed to start"
  exit 1
fi

# Give FTL some time for startup preparations
sleep 2

# Optionally attach gdb for crash backtraces (opt-in via GDB=1)
if [[ "${GDB}" == "1" ]]; then
  echo "handle SIGHUP nostop SIGPIPE nostop SIGTERM nostop SIG32 nostop SIG33 nostop SIG34 nostop SIG35 nostop SIG41 nostop" > /root/.gdbinit
  gdb -p $(cat /run/pihole-FTL.pid) --ex continue --ex "bt full" &
fi

# Print versions of pihole-FTL
echo -n "FTL version (DNS): "
dig TXT CHAOS version.FTL @127.0.0.1 +short
echo "FTL verbose version (CLI): "
/home/pihole/pihole-FTL -vv
echo -n "Contained dnsmasq version (DNS): "
dig TXT CHAOS version.bind @127.0.0.1 +short

RET=0

# Prepare BATS
if [ -z "$BATS" ]; then
  mkdir -p test/libs
  git clone --depth=1 --quiet https://github.com/bats-core/bats-core test/libs/bats-core > /dev/null
  git clone --depth=1 --quiet https://github.com/bats-core/bats-support test/libs/bats-support > /dev/null
  git clone --depth=1 --quiet https://github.com/bats-core/bats-assert  test/libs/bats-assert > /dev/null
  git clone --depth=1 --quiet https://github.com/bats-core/bats-file    test/libs/bats-file > /dev/null
  BATS=${PWD}/test/libs/bats-core/bin/bats
  # BATS_LIB_PATH needs to be an absolute path for bats to find the libraries
  BATS_LIB_PATH=${PWD}/test/libs/
  export BATS_LIB_PATH
fi

# Run BATS test suite (includes DNS, regex, CLI, config tests;
# FTL remains running for the pytest API tests afterwards)
echo "Running BATS test suite..."
$BATS -p "${bats_args[@]}" "test/test_suite.bats"
RET=$?

# Trigger network table update (PARSE_NEIGHBOR_CACHE) so mock-hwaddr
# devices like ip-127.0.0.1 exist before pytest checks them.
# RT signal offset 5 maps to PARSE_NEIGHBOR_CACHE in signals.c.
kill -SIGRTMIN+5 "$(cat /run/pihole-FTL.pid)" 2>/dev/null
sleep 2

# Run pytest API tests (FTL is still running — BATS no longer terminates it)
# Skip on riscv64 — the emulated runner is too slow for the full API suite
if [[ "${SKIP_PYTEST}" == "1" ]]; then
  echo "Skipping pytest API tests (SKIP_PYTEST=1)"
elif [[ "${CI_ARCH}" != "linux/riscv64" ]]; then
  echo "Running pytest API tests..."
  python3 -m pytest test/api/ -v
  PYTEST_RET=$?
  if [[ $PYTEST_RET != 0 ]]; then
    RET=$PYTEST_RET
  fi
else
  echo "Skipping pytest API tests (too slow on ${CI_ARCH})"
fi

# Run final BATS suite — log validation and FTL termination
# This runs after both test_suite.bats and pytest to catch any
# unexpected log messages from the entire run, then terminates FTL.
echo ""
echo "Running final log validation..."
$BATS -p "${bats_args[@]}" "test/test_final.bats"
FINAL_RET=$?
if [[ $FINAL_RET != 0 ]]; then
  RET=$FINAL_RET
fi

curl_to_tricorder() {
  curl --silent --upload-file "${1}" https://tricorder.pi-hole.net
}

if [[ -n "${LOG_DIR}" ]]; then
  mkdir -p "${LOG_DIR}"
  cp /var/log/pihole/pihole.log /var/log/pihole/FTL.log /var/log/pihole/webserver.log \
     ./ptr.log /etc/pihole/pihole.toml "${LOG_DIR}/" 2>/dev/null
  echo "Logs copied to ${LOG_DIR}"
fi

if [[ $RET != 0 && "${NO_UPLOAD}" != "1" ]]; then
  echo -n "pihole/pihole.log: "
  curl_to_tricorder /var/log/pihole/pihole.log
  echo ""
  echo -n "pihole/FTL.log: "
  curl_to_tricorder /var/log/pihole/FTL.log
  echo ""
  echo -n "ptr.log: "
  curl_to_tricorder ./ptr.log
  echo ""
  echo -n "webserver.log: "
  curl_to_tricorder /var/log/pihole/webserver.log
  echo ""
  echo -n "pihole.toml: "
  curl_to_tricorder /etc/pihole/pihole.toml
  echo ""
fi

# Restore umask
umask "$OLDUMASK"

# Run performance tests (opt-in via RUN_PERF_TEST=1)
if [[ "${RUN_PERF_TEST}" == "1" ]]; then
  if ! su pihole -s /bin/sh -c "/home/pihole/pihole-FTL --perf"; then
    echo "pihole-FTL --perf failed to start"
  fi
fi

# Remove copied file
rm /home/pihole/pihole-FTL

# Stop local powerDNS resolver
killall pdns_server
killall pdns_recursor

# Exit with return code of bats tests
exit $RET
