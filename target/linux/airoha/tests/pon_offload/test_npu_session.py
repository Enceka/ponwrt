#!/usr/bin/env python3
"""Run the production session CLI with in-memory evidence and mocked SSH/UDP."""
import contextlib
import io
import json
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import unittest
from unittest import mock

import run_npu_session as runner


BOOT = '986bed54-e67d-4baa-ac06-0627f74789a2'
OUTPUT = Path('/tmp/npu-session-host-evidence')
RELEASE = 'echo release > ' + runner.FLOW
START = "echo 'start 123 456' > " + runner.FLOW
CONNTRACK = ('nft flush chain ip pon_session forward; /usr/sbin/conntrack'
             ' -D -p udp --orig-src 192.0.2.1 --orig-dst 192.0.2.2 --sport 49152 --dport 49153')
TABLE = 'nft delete table ip pon_session'


class SessionPeer:
    def __init__(self):
        self.owner = False
        self.probe_owner = False
        self.bound = False
        self.withdrawn = False
        self.retain_owner = False
        self.static = False
        self.frozen_timestamp = False
        self.sequence = 0
        self.cpu_packets = 0
        self.clock = 0.0
        self.commands = []
        self.failures = {}
        self.files = {}
        self.console = io.StringIO()
        self.sock = mock.Mock()
        self.sock.recvfrom.side_effect = self.receive
        self.report = None
        self.summary = None
        self.error = None
        self.report_error = None

    def sleep(self, seconds):
        self.clock += seconds

    def receive(self, size):
        assert size == 2048
        return (struct.pack('!5I', 0x4354504e, self.sequence, 789, 0, 128) + bytes(66),
                ('192.168.1.1', 49152))

    def state(self):
        header = (f'cookie={123 if self.owner else 0} serial={456 if self.owner else 0} '
                  f'phase={15 if self.bound else 0} bound={int(self.bound)} hash=23 error=0\n')
        return header + ('' if self.withdrawn else 'candidate cookie=123 serial=456 service=8500\n')

    def remote(self, argv, **kwargs):
        assert argv[0] == 'ssh' and 'StrictHostKeyChecking=yes' in argv
        assert kwargs == dict(capture_output=True, text=True, timeout=20)
        guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + BOOT +
                 '; test "$(wc -l </proc/mtd)" = 1; ')
        assert argv[-1].startswith(guard)
        command = argv[-1][len(guard):]
        self.commands.append(command)
        if command == START:
            self.owner = True
        failure = self.failures.get(command)
        if isinstance(failure, Exception):
            raise failure
        if failure:
            return subprocess.CompletedProcess(argv, failure, '', 'injected failure: ' + command)
        output = ''
        if command == 'cat ' + runner.PROBE + 'status':
            output = (f'production_session=1 configured=1 mapped_service=8500 npu_owner={int(self.probe_owner)} '
                      f'sequence={self.sequence} rx_data={self.cpu_packets} rx_delivered={self.cpu_packets}\n')
        elif command == 'cat ' + runner.FLOW:
            output = self.state()
        elif command == 'nft list table ip pon_session':
            output = 'table ip pon_session {}\n'
        elif command == "echo 'send-fixed ipv4 0 tx' > " + runner.PROBE + 'command':
            self.sequence += 1
            if self.owner and not self.withdrawn:
                self.bound = True
            else:
                self.cpu_packets += 1
        elif command == START:
            pass
        elif command == RELEASE:
            self.owner = self.retain_owner
            self.bound = False
        elif command == TABLE or command.startswith('nft flush chain ip pon_session forward; '):
            self.withdrawn = True
            self.bound = False
        elif command == 'cat /sys/kernel/debug/ppe/entries':
            if self.bound:
                ib1 = 0x61000000 | (1 if self.frozen_timestamp else self.sequence)
                if self.static:
                    ib1 |= 1 << 31
                output = ('00017 BND IPv4 5T orig=192.0.2.1:49152->192.0.2.2:49153 '
                          'new=192.168.1.1:49152->192.168.1.120:49153 '
                          f'ib1={ib1:08x}\n')
        else:
            raise AssertionError('unexpected remote command: ' + command)
        return subprocess.CompletedProcess(argv, 0, output, '')

    def save(self, path, text):
        assert path.parent == OUTPUT, path
        if path.name == 'report.json' and self.report_error:
            raise self.report_error
        self.files[path.name] = json.loads(text)
        return len(text)

    def run(self, *extra):
        arguments = ['run_npu_session.py', '--pin', '/tmp/mock-pin', '--key', '/tmp/mock-key',
                     '--boot', BOOT, '--output', str(OUTPUT), '--seconds', '35', *extra]
        with (mock.patch.object(sys, 'argv', arguments),
              mock.patch.object(runner.subprocess, 'run', side_effect=self.remote),
              mock.patch.object(runner.socket, 'socket', return_value=self.sock),
              mock.patch.object(runner.time, 'sleep', side_effect=self.sleep),
              mock.patch.object(runner.time, 'monotonic', side_effect=lambda: self.clock),
              mock.patch.object(Path, 'mkdir'),
              mock.patch.object(Path, 'write_text', autospec=True, side_effect=self.save),
              contextlib.redirect_stdout(self.console)):
            try:
                runner.main()
            except Exception as error:
                self.error = error
        self.report = self.files.get('report.json')
        if self.console.getvalue():
            self.summary = json.loads(self.console.getvalue().splitlines()[-1])
        return self


class SessionTests(unittest.TestCase):
    def test_success_both_withdrawal_modes(self):
        for arguments, command, mode in (((), CONNTRACK, 'conntrack'),
                                         (('--withdraw', 'table'), TABLE, 'table')):
            with self.subTest(mode=mode):
                peer = SessionPeer().run(*arguments)
                self.assertIsNone(peer.error)
                self.assertTrue(peer.report['passed'])
                self.assertTrue(peer.report['released'])
                self.assertTrue(peer.summary['passed'])
                self.assertEqual(peer.report['withdraw'], mode)
                self.assertEqual(peer.report['seconds'], 35)
                self.assertGreaterEqual(peer.report['bound_seconds'], 35)
                self.assertEqual(len(peer.report['observations']), 35)
                self.assertEqual(len(peer.report['timestamps']), 35)
                self.assertEqual(peer.report['initial_session']['cookie'], '0')
                self.assertEqual(peer.report['final_session']['cookie'], '0')
                self.assertEqual(peer.commands.count(command), 1)
                self.assertNotIn(TABLE if mode == 'conntrack' else CONNTRACK, peer.commands)
                self.assertEqual(peer.commands.count(RELEASE), 1)
                self.assertLess(peer.commands.index(command), peer.commands.index(RELEASE))
                peer.sock.bind.assert_called_once_with(('192.168.1.120', 49153))
                peer.sock.settimeout.assert_called_once_with(3)
                peer.sock.sendto.assert_called_once_with(b'PON_SESSION_REPLY', ('192.168.1.1', 49152))
                peer.sock.close.assert_called_once()
                evidence = [value for name, value in peer.files.items() if name != 'report.json']
                self.assertEqual(len(evidence), len(peer.commands))
                self.assertTrue(all(value['returncode'] == 0 for value in evidence))

    def test_existing_owner_is_never_released(self):
        for probe_owner in (False, True):
            with self.subTest(probe_owner=probe_owner):
                peer = SessionPeer()
                peer.owner = True
                peer.probe_owner = probe_owner
                peer.run()
                self.assertIsInstance(peer.error, ValueError)
                self.assertTrue(peer.owner)
                self.assertNotIn(START, peer.commands)
                self.assertNotIn(RELEASE, peer.commands)
                self.assertFalse(peer.report['start_attempted'])
                self.assertFalse(peer.report['passed'])
                peer.sock.close.assert_called_once()

    def test_start_failure_and_lost_ack_attempt_cleanup(self):
        for failure in (1, subprocess.TimeoutExpired('mock SSH start', 20)):
            with self.subTest(failure=failure):
                peer = SessionPeer()
                peer.failures[START] = failure
                peer.run()
                self.assertIsNotNone(peer.error)
                self.assertTrue(peer.report['start_attempted'])
                self.assertTrue(peer.report['released'])
                self.assertFalse(peer.report['passed'])
                self.assertEqual(peer.commands.count(RELEASE), 1)
                evidence = next(value for value in peer.files.values() if value.get('command') == START)
                if isinstance(failure, Exception):
                    self.assertIs(peer.error, failure)
                    self.assertIn('TimeoutExpired', evidence['error'])
                else:
                    self.assertEqual(evidence['returncode'], 1)
                    self.assertIn('injected failure', evidence['stderr'])

    def test_cleanup_failure_preserves_original_exception(self):
        peer = SessionPeer()
        original = subprocess.TimeoutExpired('start lost reply', 20)
        peer.failures = {START: original, RELEASE: 2}
        peer.run()
        self.assertIs(peer.error, original)
        self.assertEqual(peer.report['error'], repr(original))
        self.assertIn('CalledProcessError', peer.report['cleanup_error'])
        self.assertFalse(peer.report['passed'])
        self.assertFalse(peer.report['released'])
        peer.sock.close.assert_called_once()

    def test_release_failure_makes_successful_exercise_fail(self):
        for retain_owner in (False, True):
            with self.subTest(retain_owner=retain_owner):
                peer = SessionPeer()
                peer.retain_owner = retain_owner
                if not retain_owner:
                    peer.failures[RELEASE] = 1
                peer.run()
                self.assertIsNotNone(peer.error)
                self.assertIn('cleanup_error', peer.report)
                self.assertFalse(peer.report['passed'])
                self.assertFalse(peer.report['released'])
                self.assertFalse(peer.summary['passed'])
                self.assertIn('withdrawal', peer.report)

    def test_socket_bind_failure_is_reported_without_release(self):
        peer = SessionPeer()
        original = OSError('address already in use')
        peer.sock.bind.side_effect = original
        peer.run()
        self.assertIs(peer.error, original)
        self.assertEqual(peer.report['error'], repr(original))
        self.assertEqual(peer.commands, [])
        peer.sock.close.assert_called_once()

    def test_socket_close_and_report_failure_preserve_original(self):
        peer = SessionPeer()
        original = subprocess.TimeoutExpired('start lost reply', 20)
        peer.failures[START] = original
        peer.sock.close.side_effect = OSError('close failed')
        peer.report_error = OSError('evidence disk full')
        peer.run()
        self.assertIs(peer.error, original)
        self.assertIsNone(peer.report)
        self.assertFalse(peer.summary['passed'])
        self.assertEqual(peer.summary['error'], repr(original))
        self.assertIn('close failed', peer.summary['socket_error'])
        self.assertIn('evidence disk full', peer.summary['report_error'])

    def test_udp_timeout_after_start_releases_owner(self):
        peer = SessionPeer()
        original = TimeoutError('UDP receive timed out')

        def receive(size):
            if peer.owner:
                raise original
            return peer.receive(size)

        peer.sock.recvfrom.side_effect = receive
        peer.run()
        self.assertIs(peer.error, original)
        self.assertEqual(peer.report['error'], repr(original))
        self.assertTrue(peer.report['released'])
        self.assertFalse(peer.report['passed'])
        peer.sock.close.assert_called_once()

    def test_exit_failure_alone_fails_the_run(self):
        for operation in ('socket', 'report'):
            with self.subTest(operation=operation):
                peer = SessionPeer()
                original = OSError(operation + ' failed')
                if operation == 'socket':
                    peer.sock.close.side_effect = original
                else:
                    peer.report_error = original
                peer.run()
                self.assertIs(peer.error, original)
                self.assertTrue(peer.summary['released'])
                self.assertFalse(peer.summary['passed'])
                self.assertEqual(peer.summary[operation + '_error'], repr(original))

    def test_duration_rejected_before_io(self):
        for seconds in ('34', '91'):
            with self.subTest(seconds=seconds):
                peer = SessionPeer().run('--seconds', seconds)
                self.assertIsInstance(peer.error, ValueError)
                self.assertIn('duration', str(peer.error))
                self.assertEqual(peer.files, {})
                self.assertEqual(peer.commands, [])
                peer.sock.bind.assert_not_called()

    def test_only_first_line_supplies_session_fields(self):
        text = ('cookie=0 serial=0 phase=0 bound=0 hash=4294967295 error=0\n'
                'candidate cookie=123 serial=456 service=8500 bound=1 error=-5\n')
        current = runner.session_fields(text)
        self.assertEqual((current['cookie'], current['serial'], current['bound'], current['error']),
                         ('0', '0', '0', '0'))
        for malformed in ('', 'cookie=0\nbound=0 serial=0 phase=0 hash=0 error=0'):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                runner.session_fields(malformed)

    def test_timestamp_failures_release_owner_and_retain_evidence(self):
        for attribute, message in (('static', 'bound row is static'),
                                   ('frozen_timestamp', 'timestamp did not advance')):
            with self.subTest(attribute=attribute):
                peer = SessionPeer()
                setattr(peer, attribute, True)
                peer.run()
                self.assertIsInstance(peer.error, ValueError)
                self.assertIn(message, str(peer.error))
                self.assertTrue(peer.report['released'])
                self.assertEqual(peer.report['hardware_hash'], 23)
                self.assertFalse(peer.report['passed'])
                if attribute == 'frozen_timestamp':
                    self.assertEqual(peer.report['timestamps'], [1] * 35)

    def test_conntrack_path_quoted_and_withdraw_failure_reported(self):
        path = '/tmp/conntrack tool; false'
        command = CONNTRACK.replace('/usr/sbin/conntrack', shlex.quote(path))
        peer = SessionPeer()
        peer.failures[command] = 1
        peer.run('--conntrack', path)
        self.assertIsInstance(peer.error, subprocess.CalledProcessError)
        self.assertIn(command, peer.commands)
        self.assertTrue(peer.report['released'])
        self.assertFalse(peer.report['passed'])
        self.assertEqual(len(peer.report['observations']), 35)


if __name__ == '__main__':
    unittest.main()
