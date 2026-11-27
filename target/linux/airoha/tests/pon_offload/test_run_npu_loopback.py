#!/usr/bin/env python3
"""Replay the real NPU runner with in-memory files and a simulated SSH peer."""
import contextlib
import hashlib
import io
import json
import shlex
import struct
import subprocess
import sys
import unittest
from unittest import mock

import run_npu_loopback as runner


BOOT = '986bed54-e67d-4baa-ac06-0627f74789a2'
MODULE = b'synthetic-npu-loopback-module'
MODULE_SHA = hashlib.sha256(MODULE).hexdigest()
FIRMWARE_SHA = hashlib.sha256(b'synthetic-npu-firmware').hexdigest()
IPV6 = '/proc/sys/net/ipv6/conf/pon0/disable_ipv6'
RELEASE = 'echo release > ' + runner.DIAG
RESTORE = 'echo restore > ' + runner.PROBE + 'command'
SNAPSHOT = ('cat ' + runner.DIAG + '; cat ' + runner.PROBE +
            'status; dmesg | tail -60')
CLASSIFIER = ('saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0 '
              'tuple=0 pool=00000000 pool_pending=0 leases=0\n')


class MemoryPath:
    def __init__(self, name, files, directories):
        self.name = str(name)
        self.files = files
        self.directories = directories

    def __str__(self):
        return self.name

    def __truediv__(self, name):
        return MemoryPath(self.name + '/' + str(name), self.files, self.directories)

    def resolve(self):
        return self

    def mkdir(self, parents=False, exist_ok=False):
        if self.name in self.directories and not exist_ok:
            raise FileExistsError(self.name)
        self.directories.add(self.name)

    def read_bytes(self):
        return self.files[self.name]

    def write_bytes(self, content):
        self.files[self.name] = bytes(content)
        return len(content)

    def write_text(self, content):
        self.write_bytes(content.encode())
        return len(content)


def render(values):
    return ' '.join(f'{name}={value}' for name, value in values.items()) + '\n'


class BoardFixture:
    def __init__(self, failures=(), snapshot_timeout=False, start_error=False,
                 identity_fault=None, closed_drift=False, observation_delay=0,
                 corrupt_restore=False, send_error=None, auth_qdma_fault=False, learn_fault=None):
        self.failures = set(failures)
        self.snapshot_timeout = snapshot_timeout
        self.start_error = start_error
        self.identity_fault = identity_fault
        self.closed_drift = closed_drift
        self.observation_delay = observation_delay
        self.corrupt_restore = corrupt_restore
        self.send_error = send_error
        self.auth_qdma_fault = auth_qdma_fault
        self.auth_mode = False
        self.learn_mode = False
        self.learn_fault = learn_fault
        self.learned = False
        self.commands = []
        self.sent = []
        self.loaded = False
        self.prepared = False
        self.was_prepared = False
        self.owner = False
        self.ring = False
        self.ipv6 = '0'
        self.service = None
        self.epoch = 6
        self.generation = 11
        self.consumed = 0
        self.pending_reads = 0
        self.last_er = None

    def diag(self):
        state = dict(owner=int(self.owner), diagnostic=int(self.owner), qualified=0,
                     policy=0, fallback=0, route_owner=int(self.owner), fe_owner=int(self.owner),
                     flow=('00002000' if self.learn_mode and self.ring else '00000000') if self.owner else '00003200',
                     tb='83c0cfb4', learn_mode=int(self.learn_mode),
                     next_row=0 if self.learn_mode and self.ring else 8192,
                     scope='01000004' if self.ring else '01000000', ingress=int(self.ring),
                     ports='01000004' if self.ring else '01000000',
                     gdm2='07f08888' if self.ring else '07f05555',
                     phase=15 if self.ring else 9,
                     gate_error=0, gate_caps=15, gate_epoch=self.epoch,
                     gate_generation=self.generation, gate_mask=4 if self.ring else 0,
                     gate_closed=int(not self.ring), gate_fault=0,
                     auth_error=0, auth_caps=7, auth_epoch=self.epoch,
                     auth_generation=self.generation, auth_count=int(self.auth_mode and self.ring),
                     auth_mode=int(self.auth_mode),
                     auth_enabled=int(self.ring), auth_inflight=0,
                     er_error=0, er_caps=15, er_state=0, er_fault=0)
        if self.owner:
            consumed = self.consumed
            if self.ring and self.pending_reads:
                self.pending_reads -= 1
                consumed -= 1
            state.update(error=0, epoch=self.epoch, generation=self.generation,
                         invalidated=0, ring=int(self.ring), packets=consumed,
                         consumed=consumed, dropped=0, fault=0,
                         observed_produced=consumed, observed_consumed=consumed, frame_bytes=128)
            if self.last_er:
                sequence, kind = self.last_er
                frame = bytearray(128)
                offset = 14 + (40 if kind == 'ipv6' else 20) + 8
                struct.pack_into('>5I', frame, offset, 0x4354504e, sequence,
                                 123, int(kind == 'ipv6'), 128)
                buffer = 0x44000000 + 64 + 8 * 64 + ((self.consumed - 1) & 7) * 2048
                descriptor = [0x80000080, self.epoch, self.consumed, 2,
                              self.generation, 0x80000000 | self.service, buffer, 0,
                              128, 0x00e00000 | self.service, 7, 0, 0x05dc7fff, 6 << 28, 2, 0]
                state.update(er_desc='/'.join(f'{word:08x}' for word in descriptor),
                             er_frame=frame.hex())
            if self.ring and self.consumed and self.identity_fault:
                state[self.identity_fault] += 1
        return render(state)

    def probe(self):
        sequence = len(self.sent)
        kind = self.sent[-1]['kind'] if self.sent else 'ipv4'
        state = int(self.prepared)
        qdma_received = sum(packet['path'] != 'er' and
                            not (self.auth_qdma_fault and packet['path'] == 'auth') for packet in self.sent)
        last = self.sent[-1] if self.sent else {}
        msg1 = 2 << 21
        if self.learn_mode and last.get('path') == 'auth':
            msg1 |= 0x2135 if self.learn_fault == 'hash' else 0x2134
        text = (f'retained={state} controller={state} opened={state} saved={state} '
                f'error=0 pending=0 sequence={sequence} received={sequence} '
                f'rx_sequence={sequence} rx_msg0={(self.service or 0) << 14:08x} '
                f'rx_msg1={msg1:08x}\n'
                f'tx_kind={kind} tx_length=128 rx_kind={kind} rx_length=114\n')
        text += (f'tx_fixed={int(last.get("fixed", False))} tx_variant={last.get("variant", 0)} '
                 f'rx_data={qdma_received} rx_delivered={qdma_received}\n')
        for index in range(10):
            value = 0x12340000 + index + (0x100 if self.prepared else 0)
            if index == 0 and self.corrupt_restore and self.was_prepared and not self.prepared:
                value ^= 1
            text += f'{0x1700 + index * 4:04x}={value:08x} saved=00000000\n'
        return text

    def write(self, destination, value):
        if destination == IPV6:
            assert value in ('0', '1')
            self.ipv6 = value
        elif destination == runner.PROBE + 'command':
            assert self.loaded
            if value == 'prepare':
                assert not self.prepared and not self.owner and self.ipv6 == '1'
                self.prepared = self.was_prepared = True
            elif value.startswith('map '):
                assert self.prepared and not self.owner
                self.service = int(value.split()[1])
            elif value.startswith(('send-current ', 'send-fixed ')):
                assert self.prepared and self.owner and 0 <= self.service <= 65535
                kind = value.split()[1]
                assert kind in ('ipv4', 'ipv6')
                fixed = value.startswith('send-fixed ')
                variant = int(value.split()[2]) if fixed else 0
                matched = self.auth_mode and self.ring and fixed and kind == 'ipv4' and variant == 0
                if matched and self.learn_mode:
                    self.learned = True
                path = 'auth' if matched else 'er' if self.ring else 'cpu'
                self.sent.append(dict(service=self.service, kind=kind,
                                      sequence=len(self.sent) + 1, path=path, fixed=fixed, variant=variant))
                if self.ring and not matched:
                    self.consumed += 1
                    self.last_er = (len(self.sent), kind)
                    self.pending_reads = self.observation_delay
                elif not self.ring and self.closed_drift:
                    self.consumed += 1
            elif value == 'restore':
                assert not self.owner and not self.ring
                self.prepared = False
            else:
                raise AssertionError('unexpected probe command: ' + value)
        elif destination == runner.DIAG:
            if value == 'start' or value.startswith(('start-auth ', 'start-learn ')):
                assert self.prepared and not self.owner and self.service is not None
                self.owner = True
                self.auth_mode = value.startswith(('start-auth ', 'start-learn '))
                self.learn_mode = value.startswith('start-learn ')
                self.epoch += 1
                self.consumed = 0
                self.last_er = None
                self.ring = not self.start_error
            elif value == 'close':
                assert self.owner and self.ring
                self.ring = False
                if self.learn_fault != 'retained':
                    self.learned = False
            elif value == 'release':
                self.ring = self.owner = False
            else:
                raise AssertionError('unexpected diagnostic command: ' + value)
        else:
            raise AssertionError('unexpected write destination: ' + destination)

    def run(self, arguments, *, input, capture_output, timeout):
        assert arguments[0] == 'ssh' and capture_output and timeout == 30
        for option in ('BatchMode=yes', 'ConnectTimeout=5', 'StrictHostKeyChecking=yes',
                       'UserKnownHostsFile=/fixture/known-hosts',
                       'ProxyCommand=/usr/bin/nc -4 -b en6 -G 4 %h %p'):
            assert option in arguments, option
        assert arguments[-2] == 'root@192.168.1.1'
        guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + BOOT +
                 '; test "$(wc -l </proc/mtd)" = 1; ')
        assert arguments[-1].startswith(guard)
        command = arguments[-1][len(guard):]
        self.commands.append(command)
        if (command, self.commands.count(command)) in self.failures:
            return subprocess.CompletedProcess(arguments, 1, b'', b'injected command failure\n')
        if command == SNAPSHOT and self.snapshot_timeout:
            raise subprocess.TimeoutExpired(arguments, timeout)
        text = ''
        if command.startswith('cat ' + runner.DIAG + '; cat ' + runner.CLASSIFIER):
            text = (self.diag() + CLASSIFIER + f'generation={self.generation} allowed=0 failed=0\n'
                    'ram-pon-tx-disable out hi\nstate DOWN\n' + FIRMWARE_SHA + '\n')
        elif command == SNAPSHOT:
            text = self.diag() + self.probe()
        elif command == 'cat ' + runner.DIAG:
            text = self.diag()
        elif command == 'cat /sys/kernel/debug/ppe/entries':
            if self.learned and self.learn_fault != 'missing':
                state = 'BND' if self.learn_fault == 'bound' else 'UNB'
                tuples = ['192.0.2.1:49152->192.0.2.2:49153', '192.0.2.2:49152->192.0.2.2:49153',
                          '192.0.2.1:49152->192.0.2.3:49153', '192.0.2.1:49153->192.0.2.2:49153',
                          '192.0.2.1:49152->192.0.2.2:49154']
                if self.learn_fault == 'tuple':
                    tuples[0] = '192.0.2.3:49152->192.0.2.2:49153'
                text = ''.join(f'{0x2134 + index:05x} {state} IPv4 5T orig={original} ib1=00000000\n'
                               for index, original in enumerate(tuples))
        elif command == 'cat ' + runner.PROBE + 'status':
            assert self.loaded
            text = self.probe()
        elif command == 'cat ' + IPV6:
            text = self.ipv6 + '\n'
        elif command == 'test ! -d /sys/module/ct_pon_loopback; cat > /tmp/ct_pon_loopback.ko':
            assert not self.loaded and input == MODULE
        elif command.startswith('test "$(sha256sum /tmp/ct_pon_loopback.ko '):
            assert MODULE_SHA in command and command.endswith('insmod /tmp/ct_pon_loopback.ko special_tag=1')
            assert not self.loaded
            self.loaded = True
        elif command == 'rmmod ct_pon_loopback':
            assert self.loaded and not self.prepared and not self.owner and not self.ring
            self.loaded = False
        elif command.startswith('echo '):
            words = shlex.split(command)
            assert len(words) == 4 and words[2] == '>'
            self.write(words[3], words[1])
            if self.start_error and words[3] == runner.DIAG and words[1] == 'start':
                return subprocess.CompletedProcess(arguments, 1, b'', b'Input/output error\n')
            if self.send_error and words[3] == runner.PROBE + 'command' and words[1].startswith('send-current '):
                return subprocess.CompletedProcess(arguments, self.send_error[0], b'', self.send_error[1])
        else:
            raise AssertionError('unexpected remote command: ' + command)
        return subprocess.CompletedProcess(arguments, 0, text.encode(), b'')


class RunnerTests(unittest.TestCase):
    def invoke(self, board, run=True, capture_service=None, auth=False, learn=False):
        self.files = {'/fixture/module.ko': MODULE}
        directories = {'/fixture'}
        arguments = ['run_npu_loopback.py', '--pin', '/fixture/known-hosts', '--boot', BOOT,
                     '--module', '/fixture/module.ko', '--sha256', MODULE_SHA,
                     '--firmware-sha256', FIRMWARE_SHA, '--output', '/fixture/output']
        if run:
            arguments.append('--run')
        if capture_service is not None:
            arguments.extend(('--capture-service', str(capture_service)))
        if auth:
            arguments.append('--auth')
        if learn:
            arguments.append('--learn')
        stdout = io.StringIO()
        with mock.patch.object(runner, 'Path', side_effect=lambda name: MemoryPath(name, self.files, directories)), \
                mock.patch.object(sys, 'argv', arguments), \
                mock.patch.object(runner.subprocess, 'run', side_effect=board.run), \
                mock.patch.object(runner.time, 'sleep') as sleep, \
                contextlib.redirect_stdout(stdout):
            self.sleep = sleep
            runner.main()
        self.stdout = stdout.getvalue()
        return self.report() if run else json.loads(self.stdout)

    def report(self):
        return json.loads(self.files['/fixture/output/report.json'])

    def assert_restored(self, board):
        self.assertFalse(board.owner)
        self.assertFalse(board.ring)
        self.assertFalse(board.prepared)
        self.assertFalse(board.loaded)
        self.assertEqual(board.ipv6, '0')
        snapshot = board.commands.index(SNAPSHOT)
        release = board.commands.index(RELEASE, snapshot + 1)
        restore = board.commands.index(RESTORE, release + 1)
        unload = board.commands.index('rmmod ct_pon_loopback', restore + 1)
        self.assertGreater(board.commands.index('echo 0 > ' + IPV6), unload)

    def assert_matrix(self, report):
        self.assertTrue(report['matrix_passed'])
        self.assertFalse(report['pon_ppe_qualified'])
        self.assertEqual(len(report['observations']), 36)
        self.assertEqual(len(report['cpu_observations']), 4)
        for service, first in ((0, 1), (0x8000, 21)):
            er_packets = [packet for packet in report['observations'] if packet['service'] == service]
            cpu_packets = [packet for packet in report['cpu_observations'] if packet['service'] == service]
            self.assertEqual([packet['sequence'] for packet in er_packets], list(range(first, first + 18)))
            self.assertEqual([packet['er_sequence'] for packet in er_packets], list(range(1, 19)))
            self.assertEqual([packet['kind'] for packet in er_packets], ['ipv4', 'ipv6'] * 9)
            self.assertEqual([packet['sequence'] for packet in cpu_packets], [first + 18, first + 19])
            self.assertEqual([packet['kind'] for packet in cpu_packets], ['ipv4', 'ipv6'])
            self.assertEqual([packet['er_consumed'] for packet in cpu_packets], [18, 18])
            buffers = [packet['descriptor'][6] for packet in er_packets]
            self.assertEqual(len(set(buffers[:8])), 8)
            self.assertEqual(buffers[:8], buffers[8:16])
            self.assertEqual(buffers[:2], buffers[16:])
        self.assertNotEqual(report['observations'][0]['epoch'], report['observations'][18]['epoch'])

    def test_full_matrix_and_cleanup(self):
        board = BoardFixture()
        report = self.invoke(board)
        self.assert_matrix(report)
        self.assertTrue(report['passed'])
        self.assertTrue(report['restored'])
        self.assertEqual(len(board.sent), 40)
        self.assertEqual([packet['path'] for packet in board.sent], (['er'] * 18 + ['cpu'] * 2) * 2)
        self.assertEqual(board.commands.count(RELEASE), 3)
        self.assert_restored(board)
        self.assertEqual(json.loads(self.stdout), dict(passed=True, packets=36, restored=True))

    def test_preflight_does_not_prepare_or_send(self):
        board = BoardFixture()
        result = self.invoke(board, run=False)
        self.assertTrue(result['preflight'])
        self.assertEqual(len(board.commands), 1)
        self.assertEqual(board.sent, [])
        self.assertFalse(board.loaded)
        self.assertEqual(board.ipv6, '0')
        self.assertNotIn('/fixture/output/report.json', self.files)

    def test_snapshot_error_and_timeout_still_restore(self):
        for timeout in (False, True):
            with self.subTest(timeout=timeout):
                board = BoardFixture(snapshot_timeout=timeout,
                                     failures=() if timeout else ((SNAPSHOT, 1),))
                report = self.invoke(board)
                self.assert_matrix(report)
                self.assertTrue(report['passed'])
                self.assertTrue(report['restored'])
                self.assertIn('snapshot_error', report)
                self.assertNotIn('cleanup_error', report)
                self.assert_restored(board)

    def test_cleanup_release_error_keeps_module_loaded(self):
        board = BoardFixture(failures=((RELEASE, 3),))
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(board)
        report = self.report()
        self.assert_matrix(report)
        self.assertFalse(report['passed'])
        self.assertFalse(report['restored'])
        self.assertIn('cleanup_error', report)
        self.assertNotIn(RESTORE, board.commands)
        self.assertNotIn('rmmod ct_pon_loopback', board.commands)
        self.assertFalse(board.owner)
        self.assertTrue(board.loaded)
        self.assertTrue(board.prepared)

    def test_failed_service_release_retains_owner_when_cleanup_also_fails(self):
        board = BoardFixture(failures=((RELEASE, 1), (RELEASE, 2)))
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(board)
        report = self.report()
        self.assertFalse(report['matrix_passed'])
        self.assertFalse(report['passed'])
        self.assertFalse(report['restored'])
        self.assertIn('error', report)
        self.assertIn('cleanup_error', report)
        self.assertTrue(board.owner)
        self.assertTrue(board.loaded)
        self.assertTrue(board.prepared)
        self.assertNotIn(RESTORE, board.commands)

    def test_restore_and_unload_errors_keep_overall_failed(self):
        for command in (RESTORE, 'rmmod ct_pon_loopback', 'echo 0 > ' + IPV6):
            with self.subTest(command=command):
                board = BoardFixture(failures=((command, 1),))
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke(board)
                report = self.report()
                self.assert_matrix(report)
                self.assertFalse(report['passed'])
                self.assertFalse(report['restored'])
                self.assertIn('cleanup_error', report)
                self.assertFalse(board.owner)

    def test_restored_register_mismatch_blocks_unload(self):
        board = BoardFixture(corrupt_restore=True)
        with self.assertRaisesRegex(ValueError, 'loopback register restore mismatch'):
            self.invoke(board)
        self.assert_matrix(self.report())
        self.assertFalse(self.report()['passed'])
        self.assertFalse(self.report()['restored'])
        self.assertIn('cleanup_error', self.report())
        self.assertTrue(board.loaded)
        self.assertNotIn('rmmod ct_pon_loopback', board.commands)

    def test_start_eio_after_claim_is_released(self):
        board = BoardFixture(start_error=True)
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(board)
        report = self.report()
        self.assertFalse(report['matrix_passed'])
        self.assertFalse(report['passed'])
        self.assertTrue(report['restored'])
        self.assertEqual(report['observations'], [])
        self.assertEqual(report['cpu_observations'], [])
        self.assertEqual(board.sent, [])
        self.assert_restored(board)

    def test_start_failure_survives_snapshot_failure(self):
        board = BoardFixture(start_error=True, failures=((SNAPSHOT, 1),))
        with self.assertRaises(subprocess.CalledProcessError) as raised:
            self.invoke(board)
        report = self.report()
        self.assertIn('echo start > ' + runner.DIAG, raised.exception.cmd[-1])
        self.assertIn('snapshot_error', report)
        self.assertIn('error', report)
        self.assertFalse(report['passed'])
        self.assertTrue(report['restored'])
        self.assert_restored(board)

    def test_identity_mismatch_fails_matrix_and_still_restores(self):
        for name in ('gate_epoch', 'gate_generation', 'auth_epoch', 'auth_generation'):
            with self.subTest(name=name):
                board = BoardFixture(identity_fault=name)
                with self.assertRaisesRegex(ValueError, 'GATE/AUTH transaction identity mismatch'):
                    self.invoke(board)
                report = self.report()
                self.assertFalse(report['matrix_passed'])
                self.assertFalse(report['passed'])
                self.assertTrue(report['restored'])
                self.assertEqual(report['observations'], [])
                self.assert_restored(board)

    def test_cpu_packet_cannot_advance_closed_er(self):
        board = BoardFixture(closed_drift=True)
        with self.assertRaisesRegex(ValueError, 'closed path resumed'):
            self.invoke(board)
        report = self.report()
        self.assertFalse(report['matrix_passed'])
        self.assertFalse(report['passed'])
        self.assertTrue(report['restored'])
        self.assertEqual(len(report['observations']), 18)
        self.assertEqual(report['cpu_observations'], [])
        self.assert_restored(board)

    def test_delayed_er_observation_retries(self):
        board = BoardFixture(observation_delay=1)
        report = self.invoke(board)
        self.assert_matrix(report)
        self.assertTrue(report['passed'])
        self.assertEqual(self.sleep.call_count, 36)
        self.assert_restored(board)

    def test_auth_matches_qdma_and_mismatches_er(self):
        board = BoardFixture()
        report = self.invoke(board, auth=True)
        self.assertTrue(report['passed'])
        self.assertTrue(report['restored'])
        self.assertEqual(len(report['auth_observations']), 32)
        self.assertEqual(sum(entry['matched'] for entry in report['auth_observations']), 8)
        self.assertEqual(len(report['observations']), 24)
        self.assertEqual(len(report['cpu_observations']), 4)
        for service in (0, 0x8000):
            packets = [packet for packet in report['observations'] if packet['service'] == service]
            self.assertEqual([packet['er_sequence'] for packet in packets], list(range(1, 13)))
        self.assert_restored(board)

    def test_auth_requires_qdma_evidence_for_match(self):
        board = BoardFixture(auth_qdma_fault=True)
        with self.assertRaisesRegex(ValueError, 'AUTH match missing QDMA receive'):
            self.invoke(board, auth=True)
        self.assertFalse(self.report()['passed'])
        self.assertTrue(self.report()['restored'])
        self.assert_restored(board)

    def test_learning_requires_exact_unbound_row_and_cleanup(self):
        board = BoardFixture()
        report = self.invoke(board, learn=True)
        self.assertTrue(report['passed'])
        self.assertEqual([row['hash'] for row in report['learned_rows']], [0x2134, 0x2134])
        self.assertEqual([row['service'] for row in report['learned_rows']], [0, 0x8000])
        self.assert_restored(board)

    def test_learning_rejects_missing_wrong_or_retained_rows(self):
        for fault in ('missing', 'tuple', 'bound', 'retained', 'hash'):
            with self.subTest(fault=fault):
                board = BoardFixture(learn_fault=fault)
                with self.assertRaises(ValueError):
                    self.invoke(board, learn=True)
                self.assertFalse(self.report()['passed'])
                self.assertTrue(self.report()['restored'])
                self.assert_restored(board)

    def test_capture_success_and_expected_timeout_restore(self):
        for service in (0, 1, 0x8000, 0xffff):
            for send_error in (None, (1, b'ash: write error: Operation timed out\n')):
                with self.subTest(service=service, send_error=send_error):
                    board = BoardFixture(send_error=send_error)
                    report = self.invoke(board, capture_service=service)
                    self.assertTrue(report['capture_completed'])
                    self.assertFalse(report['matrix_passed'])
                    self.assertFalse(report['passed'])
                    self.assertTrue(report['restored'])
                    self.assertEqual(report['observations'], [])
                    self.assertEqual(report['cpu_observations'], [])
                    self.assertEqual([entry['kind'] for entry in report['captures']], ['ipv4', 'ipv6'])
                    for entry in report['captures']:
                        self.assertEqual(entry['descriptor'][9] & 0xffff, service)
                        self.assertEqual(entry['send_error'], 'RX marker timed out' if send_error else None)
                    self.assert_restored(board)

    def test_capture_unexpected_send_error_fails_and_restores(self):
        for send_error in ((1, b'Input/output error\n'),
                           (255, b'ash: write error: Operation timed out\n'),
                           (1, b'ash: write error: Operation timed out\nextra error\n')):
            with self.subTest(send_error=send_error):
                board = BoardFixture(send_error=send_error)
                with self.assertRaisesRegex(ValueError, 'unexpected capture send failure'):
                    self.invoke(board, capture_service=0x2134)
                report = self.report()
                self.assertFalse(report['passed'])
                self.assertTrue(report['restored'])
                self.assertNotIn('capture_completed', report)
                self.assertEqual(report['captures'], [])
                self.assert_restored(board)

    def test_capture_cleanup_failure_is_reported(self):
        board = BoardFixture(failures=((RELEASE, 1),))
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(board, capture_service=1)
        report = self.report()
        self.assertTrue(report['capture_completed'])
        self.assertFalse(report['passed'])
        self.assertFalse(report['restored'])
        self.assertIn('cleanup_error', report)
        self.assertTrue(board.owner)
        self.assertTrue(board.loaded)
        self.assertNotIn(RESTORE, board.commands)

    def test_capture_service_range_checked_before_ssh(self):
        for service in (-1, 65536):
            with self.subTest(service=service):
                board = BoardFixture()
                with self.assertRaisesRegex(ValueError, 'capture service out of range'):
                    self.invoke(board, capture_service=service)
                self.assertEqual(board.commands, [])

    def test_er_observation_retry_is_bounded(self):
        board = BoardFixture(observation_delay=20)
        with self.assertRaisesRegex(ValueError, 'diagnostic state: packets'):
            self.invoke(board)
        self.assertEqual(self.sleep.call_count, 10)
        self.assertEqual(len(board.sent), 1)
        self.assertFalse(self.report()['passed'])
        self.assertTrue(self.report()['restored'])
        self.assert_restored(board)


if __name__ == '__main__':
    unittest.main()
