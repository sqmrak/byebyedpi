#!/usr/bin/env bash
# the daemon and byebyectl on the host: the control path, the config file and
# the answers of a start that cannot open a utun here
set -euo pipefail

cd "$(dirname "$0")"
work="$(mktemp -d)"
sock="${work}/ctl.sock"
cfg="${work}/byebyedpi.cfg"
pid=""
cleanup() {
    [ -z "${pid}" ] || kill "${pid}" 2>/dev/null || true
    [ -z "${pid}" ] || wait "${pid}" 2>/dev/null || true
    rm -rf "${work}"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ctl() { ./byebyectl-host --ctl "${sock}" "$@"; }

openssl req -x509 -newkey rsa:2048 -nodes -keyout "${work}/key.pem" -out "${work}/ca.pem" -days 2 \
    -subj /CN=smoke >/dev/null 2>&1 || fail "no throwaway trust root"

./byedpid-host --ctl "${sock}" --config "${cfg}" --ca "${work}/ca.pem" 2>"${work}/log" &
pid=$!
for _ in $(seq 1 50); do [ -S "${sock}" ] && break; sleep 0.1; done
[ -S "${sock}" ] || fail "the control socket never appeared: $(cat "${work}/log")"

ctl version | grep -q '^OK byebyedpi' || fail "version"
status="$(ctl status)"
grep -q '^running=0$' <<<"${status}" || fail "status says running before a start"
grep -q '^config_error=$' <<<"${status}" || fail "a missing config file is not an error"

config="$(ctl config)"
if grep -q '^desync = ' <<<"${config}"; then fail "the bypass switch is still in the config"; fi
if ctl set desync off >"${work}/out" 2>&1; then fail "the bypass was switched off"; fi
grep -q '^quic = block$' <<<"${config}" || fail "default quic"

ctl set quic pass | grep -q '^OK' || fail "set quic"
ctl set dns 9.9.9.9 | grep -q '^OK' || fail "set dns"
ctl set desync.spec 'split=2,mid' | grep -q '^OK' || fail "set spec"
if ctl set quic maybe >"${work}/out" 2>&1; then fail "a bad value was accepted"; fi
grep -q 'quic is block or pass' "${work}/out" || fail "the bad value's reason: $(cat "${work}/out")"
if ctl set colour blue >"${work}/out" 2>&1; then fail "an unknown key was accepted"; fi
grep -q 'unknown key' "${work}/out" || fail "the unknown key's reason"
grep -q '^quic = pass$' "${cfg}" || fail "the file was not written"
grep -q '^dns = 9.9.9.9$' "${cfg}" || fail "the file lost the dns"
grep -q '^desync.spec = split=2,mid$' "${cfg}" || fail "the file lost the spec"
[ "$(stat -c %a "${cfg}")" = "644" ] || fail "config mode"

ctl set desync.spec '-d1 -s5+s -r1+s -S -a1 -As -d2' | grep -q '^OK' || fail "set ciadpi options"
grep -q '^desync.spec = -d1 -s5+s -r1+s -S -a1 -As -d2$' "${cfg}" || fail "the file lost the ciadpi options"
grep -q 'desync.spec: -a: fake udp packets are not sent' "${work}/log" || fail "the left out options are not logged: $(cat "${work}/log")"
if ctl set desync.spec '-d1 -s' >"${work}/out" 2>&1; then fail "options with no value were accepted"; fi
grep -q 'option -s needs a value' "${work}/out" || fail "the option's reason: $(cat "${work}/out")"
grep -q '^desync.spec = -d1 -s5+s -r1+s -S -a1 -As -d2$' "${cfg}" || fail "a bad option line replaced the old one"
# one strategy only: a list is refused, and the old text stays
if ctl set desync.spec 'split=1 | none' >"${work}/out" 2>&1; then fail "a strategy list was accepted"; fi
grep -q 'one strategy' "${work}/out" || fail "the list's reason: $(cat "${work}/out")"
grep -q '^desync.spec = -d1 -s5+s -r1+s -S -a1 -As -d2$' "${cfg}" || fail "a refused list replaced the old text"
ctl set desync.spec 'split=1' | grep -q '^OK' || fail "set one strategy"
ctl set hosts blocked.txt | grep -q '^OK' || fail "set hosts"
ctl set hosts.mode except | grep -q '^OK' || fail "set hosts.mode"
ctl set telegram.pool 2 | grep -q '^OK' || fail "set telegram.pool"
if ctl set hosts ../escape >"${work}/out" 2>&1; then fail "a path was accepted as a hosts name"; fi
grep -q 'hosts is a file name or none' "${work}/out" || fail "the hosts reason: $(cat "${work}/out")"
if ctl set desync.spec '' >"${work}/out" 2>&1; then fail "an empty strategy was accepted"; fi
grep -q '^desync.spec = split=1$' "${cfg}" || fail "the file lost the strategy"
grep -q '^hosts = blocked.txt$' "${cfg}" || fail "the file lost hosts"
grep -q '^hosts.mode = except$' "${cfg}" || fail "the file lost hosts.mode"
grep -q '^telegram.pool = 2$' "${cfg}" || fail "the file lost telegram.pool"

# the local telegram proxy follows its own keys at once and keeps its secret
ctl status | grep -q '^proxy=0$' || fail "the proxy runs by default"
ctl status | grep -q '^strategy=$' || fail "a strategy is reported with no tunnel"
port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
ctl set proxy.port "${port}" | grep -q '^OK$' || fail "set proxy.port"
ctl set proxy on | grep -q '^OK$' || fail "set proxy: $(cat "${work}/log")"
ctl status | grep -q '^proxy=1$' || fail "the proxy did not start: $(cat "${work}/log")"
secret="$(sed -n 's/^proxy.secret = //p' "${cfg}")"
[[ "${secret}" =~ ^[0-9a-f]{32}$ ]] || fail "no secret was drawn: ${secret}"
python3 -c "import socket; socket.create_connection(('127.0.0.1', ${port}), 2).close()" || fail "nothing listens on the proxy port"
ctl set proxy off | grep -q '^OK$' || fail "set proxy off"
ctl status | grep -q '^proxy=0$' || fail "the proxy did not stop"
if python3 -c "import socket; socket.create_connection(('127.0.0.1', ${port}), 1)" 2>/dev/null; then fail "the proxy port is still open"; fi
ctl set proxy on | grep -q '^OK$' || fail "set proxy on again"
[ "$(sed -n 's/^proxy.secret = //p' "${cfg}")" = "${secret}" ] || fail "the secret changed between starts"
# a port the daemon cannot bind is said, not hidden (root can bind it)
ctl set proxy.port 1 | grep -q '^OK$' || fail "move the proxy"
if [ "$(id -u)" != 0 ]; then
    ctl status | grep -q '^proxy.error=cannot bind 127.0.0.1 (port 1)' || fail "the bind failure is not said"
    ctl status | grep -q '^proxy=0$' || fail "a proxy that could not bind is reported running"
fi
ctl set proxy off | grep -q '^OK$' || fail "set proxy off at the end"

# the strategy check: no probe yet, a bad name, then a run against a closed port
ctl probe | grep -q '^state=idle$' || fail "a probe before any run"
if ctl probe 'a/b' >"${work}/out" 2>&1; then fail "a bad name was probed"; fi
grep -q 'usage: probe NAME' "${work}/out" || fail "the probe usage: $(cat "${work}/out")"
if ctl probe a.org b.org c.org d.org e.org >"${work}/out" 2>&1; then fail "five names were probed"; fi
ctl probe stop | grep -q '^OK' || fail "probe stop"
ctl probe localhost >"${work}/out" 2>"${work}/err" || fail "probe localhost: $(cat "${work}/out")"
grep -q '^state=done$' "${work}/out" || fail "the probe did not finish: $(cat "${work}/out")"
grep -q '^configured=1$' "${work}/out" || fail "the probe ignored the configured strategy"
grep -q '^candidate.0=0/1 0ms split=1$' "${work}/out" || fail "the first candidate: $(cat "${work}/out")"
grep -q '^suggest=$' "${work}/out" || fail "a closed port suggested something"
grep -q 'progress=' "${work}/err" || fail "no progress on stderr"

printf 'colour = blue\n' >"${cfg}"
if ctl reload >"${work}/out" 2>&1; then fail "a bad file was accepted"; fi
grep -q 'line 1: unknown key' "${work}/out" || fail "the bad file's reason: $(cat "${work}/out")"
ctl status | grep -q '^config_error=line 1: unknown key$' || fail "status hides the bad config"
printf 'quic = pass\n' >"${cfg}"
ctl reload | grep -q '^OK' || fail "reload"

# a host cannot open a utun: the start is refused, with the reason
if ctl start >"${work}/out" 2>&1; then fail "a start worked without a utun"; fi
grep -q '^ERR ' "${work}/out" || fail "start's answer: $(cat "${work}/out")"
ctl status | grep -q '^running=0$' || fail "running after a refused start"
ctl status | grep -q '^wanted=0$' || fail "a refused start is still wanted"
ctl stop | grep -q '^OK' || fail "stop"

# the token guards every command but version
token="${sock%.sock}.token"
[ -f "${token}" ] || fail "no token file"
python3 - "${sock}" <<'PY'
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
s.sendall(b"status\n")
data = s.recv(200)
assert data.startswith(b"ERR authenticate first"), data
s.sendall(b"auth 00000000000000000000000000000000\n")
data = s.recv(200)
assert data.startswith(b"ERR bad token"), data
s.sendall(b"x" * 1400 + b"\n")
data = s.recv(200)
assert b"line too long" in data, data
PY

kill -TERM "${pid}"
wait "${pid}" || true
pid=""
[ ! -e "${sock}" ] || fail "the socket was left behind"
[ ! -e "${token}" ] || fail "the token was left behind"
grep -q 'shutting down' "${work}/log" || fail "no shutdown line: $(cat "${work}/log")"
echo "ctl smoke ok"
