#!/usr/bin/env python3
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

POSTINST = Path(__file__).resolve().parents[1] / 'packaging/DEBIAN/postinst'


def function(name):
    match = re.search(r'^' + name + r'\(\) \{\n.*?^\}\n',
                      POSTINST.read_text(), re.M | re.S)
    if not match:
        raise AssertionError('missing function ' + name)
    return match.group(0)


class LaunchdInstallTests(unittest.TestCase):
    def run_installer(self, *, version='6', loaded=False, list_error=False,
                      error='launch_msg(): Socket is not connected',
                      manager='System', answers=False, rootless=False,
                      modern=False, empty_list=False):
        with tempfile.TemporaryDirectory(prefix='bye-launchd-') as directory:
            base = Path(directory)
            launchctl = base / 'launchctl'
            launchctl.write_text('''#!/bin/sh
[ -z "${LAUNCHD_SOCKET+x}" ] && [ -z "${LaunchKeepContext+x}" ] || exit 9
echo "$*" >> "$FIXTURE/calls"
case "$1" in
  list)
    [ "$LIST_ERROR" = 0 ] || exit 1
    [ "$EMPTY_LIST" = 0 ] || exit 0
    printf 'PID\\tStatus\\tLabel\\n42\\t0\\tcom.byebyedpi.byedpid.other\\n'
    [ ! -e "$FIXTURE/loaded" ] || printf '43\\t0\\tcom.byebyedpi.byedpid\\n'
    exit 0 ;;
  managername) echo "$MANAGER"; exit 0 ;;
  bootstrap)
    if [ "$MODERN" = 1 ]; then touch "$FIXTURE/loaded"; exit 0; fi ;;
  enable|kickstart|start) exit 0 ;;
esac
echo "$LOAD_ERROR" >&2
exit 0
''')
            launchctl.chmod(0o755)
            payload = base / 'payload'
            (payload / 'usr/bin').mkdir(parents=True)
            ctl = payload / 'usr/bin/byebyectl'
            ctl.write_text('''#!/bin/sh
if [ "$ANSWERS" = 1 ] || [ -e "$FIXTURE/started" ] || [ -e "$FIXTURE/loaded" ]; then
  printf 'OK\\nrunning=0\\n'
  exit 0
fi
exit 1
''')
            ctl.chmod(0o755)
            daemon = base / 'byedpid'
            daemon.write_text('#!/bin/sh\ntouch "$FIXTURE/started"\n')
            daemon.chmod(0o755)
            if loaded:
                (base / 'loaded').touch()
            functions = ''.join(function(name) for name in (
                'launchctl_cmd', 'launchd_loaded', 'launchd_attempt',
                'diagnose_launchd_load', 'byedpid_answers',
                'start_without_launchd_socket', 'launchd_start'))
            # redirect the fixed device executable into the isolated host fixture
            functions = functions.replace('/usr/bin/byedpid </dev/null',
                                          '"$FIXTURE/byedpid" </dev/null')
            script = functions + '''
firmware_major() { echo "$VERSION"; }
launchd_start
rc=$?
wait
exit "$rc"
'''
            env = dict(os.environ, FIXTURE=str(base), PAYLOAD_ROOT=str(payload),
                       LAUNCHCTL=str(launchctl), LABEL='com.byebyedpi.byedpid',
                       PLIST='/fixture/daemon.plist', LOG=str(base / 'log'),
                       JBROOT='/var/jb' if rootless else '', VERSION=version,
                       LIST_ERROR=str(int(list_error)), EMPTY_LIST=str(int(empty_list)),
                       LOAD_ERROR=error, MANAGER=manager, ANSWERS=str(int(answers)),
                       MODERN=str(int(modern)), LAUNCHD_SOCKET='/stale/socket',
                       LaunchKeepContext='1')
            result = subprocess.run(['/bin/sh', '-c', script], env=env,
                                    text=True, capture_output=True, timeout=15)
            started = (base / 'started').exists()
            log = (base / 'log').read_text()
            calls = (base / 'calls').read_text()
            return result, started, log, calls

    def test_ios6_missing_socket_starts_one_daemon(self):
        result, started, log, _ = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(started)
        self.assertIn('starting byedpid directly until reboot', log)
        self.assertIn('byedpid answered status', log)

    def test_existing_daemon_is_kept(self):
        result, started, _, _ = self.run_installer(answers=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)

    def test_loaded_job_is_kept(self):
        result, started, log, _ = self.run_installer(loaded=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)
        self.assertIn('launchd holds com.byebyedpi.byedpid', log)

    def test_modern_bootstrap_stays_managed(self):
        result, started, log, calls = self.run_installer(version='16', rootless=True, modern=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(started)
        self.assertIn('byedpid answered status', log)
        self.assertNotIn('load -w', calls)

    def test_other_failures_do_not_spawn(self):
        for options in ({'version': '9'}, {'version': '16'}, {'version': ''},
                        {'rootless': True}, {'list_error': True}, {'empty_list': True},
                        {'manager': 'Aqua'}, {'error': 'invalid plist permissions'}):
            with self.subTest(options=options):
                result, started, _, _ = self.run_installer(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(started)

    def test_tls_log_preserved_and_writable_by_mobile(self):
        with tempfile.TemporaryDirectory(prefix='bye-tls-log-') as directory:
            base = Path(directory)
            hook = base / 'hooks'
            hook.mkdir()
            payload = base / 'payload/usr/lib/byebyedpi'
            payload.mkdir(parents=True)
            (payload / 'byebyetlsfix.dylib').write_bytes(b'fixture')
            (payload / 'byebyetlsfix.plist').write_bytes(b'fixture')
            commands = base / 'bin'
            commands.mkdir()
            chown = commands / 'chown'
            chown.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$FIXTURE/owners"\n')
            chown.chmod(0o755)
            log = base / 'tls.log'
            prefs = base / 'prefs.plist'
            prefs.write_bytes(b'keep preferences')
            script = function('install_byebyetlsfix')
            script = script.replace('/var/log/byebyetlsfix.log', str(log))
            script = script.replace('/var/mobile/Library/Preferences/com.byebyedpi.byebyetlsfix.plist', str(prefs))
            script += '\ninstall_byebyetlsfix\n'
            env = dict(os.environ, FIXTURE=str(base), HOOK_DIR=str(hook),
                       PAYLOAD_ROOT=str(base / 'payload'),
                       PATH=str(commands) + os.pathsep + os.environ['PATH'])

            def install():
                return subprocess.run(['/bin/sh', '-c', script], env=env,
                                      capture_output=True, timeout=5)

            result = install()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(log.stat().st_mode & 0o777, 0o660)
            self.assertIn('root:mobile', (base / 'owners').read_text())
            log.write_bytes(b'previous handshake\n')
            self.assertEqual(install().returncode, 0)
            self.assertEqual(log.read_bytes(), b'previous handshake\n')
            self.assertEqual(prefs.read_bytes(), b'keep preferences')
            log.unlink()
            victim = base / 'other.log'
            victim.write_bytes(b'keep another file')
            log.symlink_to(victim)
            self.assertNotEqual(install().returncode, 0)
            self.assertEqual(victim.read_bytes(), b'keep another file')
            log.unlink()
            log.mkdir()
            self.assertNotEqual(install().returncode, 0)


if __name__ == '__main__':
    unittest.main()
