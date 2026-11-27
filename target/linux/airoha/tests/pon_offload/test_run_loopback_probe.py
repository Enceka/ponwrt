#!/usr/bin/env python3
"""Exercise the loopback runner with bounded, local SSH fixtures."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


RUNNER_PATH = Path(__file__).with_name('run_loopback_probe.py')
SPEC = importlib.util.spec_from_file_location('loopback_runner', RUNNER_PATH)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)
PROBE = '/sys/kernel/debug/ct_pon_loopback/'
CLASSIFIER = '/sys/bus/platform/devices/1fb50000.ethernet/ct_pon_cpu_probe'
POLICY = '/sys/bus/platform/devices/1fb50000.ethernet/ct_native_pair_policy'
CONFIG = '/sys/kernel/debug/ppe/config'
IPV6 = '/proc/sys/net/ipv6/conf/pon0/disable_ipv6'
BOOT = '986bed54-e67d-4baa-ac06-0627f74789a2'
CLEAN = 'saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0\n'
HEALTH = 'ct_cpu_fallback: 0 healthy\ngeneration=49 allowed=1 failed=0\n'
EXACT_OPTIONS = ['--run', '--special-tag', '--cover-slot', '1',
                 '--tuple-variants', '--exact-tuple', '--require-native']
ZERO_OPTIONS = ['--run', '--special-tag', '--cover-slot', '1', '--service-zero', '--require-native']


class BoardFixture:
    def __init__(self, exact=True, ring_overrides=None, corrupt=None, fail_command=None, fail_occurrence=1):
        self.exact = exact
        self.ring_overrides = ring_overrides or {}
        self.corrupt = corrupt
        self.fail_command = fail_command
        self.fail_occurrence = fail_occurrence
        self.commands = []
        self.sent = []
        self.heads = {0: 7, 2: 11, 4: 19}
        self.loaded = False
        self.prepared = False
        self.routed = False
        self.cover = False
        self.cover_slot = 1
        self.classified = False
        self.services = {}
        self.tuple_active = False
        self.ipv6 = '0'
        self.pool_clean = 'tuple=0 pool=00000000 pool_pending=0 leases=0'
        self.owner_busy = False

    def classifier_status(self):
        if not self.cover and not self.classified:
            return CLEAN + 'service0=0 service1=0 ppe=0 errors=0 cover=00 routed=0\n' + self.pool_clean + '\n'
        active = (3 << (2 * self.cover_slot) if self.cover else 0)
        active |= sum(3 << (2 * slot) for slot in self.services)
        cover = 1 << self.cover_slot if self.cover else 0
        pool = 'tuple=1 pool=00003fff pool_pending=0 leases=2' if self.tuple_active else self.pool_clean
        return (f'saved=1 dirty=0f active={active:02x} pending=0 scope=01000004 ready=1\n'
                f'service0={self.services.get(0, 0)} service1={self.services.get(1, 0)} '
                f'ppe=0 errors=0 cover={cover:02x} routed=' +
                str(int(self.routed)) + '\n ' + pool + '\n')

    def status(self):
        sequence = len(self.sent)
        service, kind, variant = self.sent[-1] if self.sent else (0, 'ipv4', 0)
        state = int(self.prepared)
        result = (f'retained={state} controller={state} opened={state} saved={state} error=0 pending=0 '
                  f'sequence={sequence} received={sequence} rx_sequence={sequence} '
                  f'rx_msg0={service << 14:08x} rx_msg1={2 << 21:08x}\n'
                  f'tx_kind={kind} tx_length=128 rx_kind={kind} rx_length=114\n'
                  f'tx_variant={variant}\n')
        result += ''.join(f'{0x1700 + 4 * index:04x}={0x12340000 + index:08x} saved=00000000\n'
                          for index in range(10))
        result += ''.join(f'rx{ring} head={head} tail=0 queued=0\n'
                          for ring, head in self.heads.items())
        return result

    def run(self, command_line, *, input, capture_output, timeout):
        if command_line[0] != 'ssh' or not capture_output or timeout != 25:
            raise AssertionError('unexpected subprocess invocation')
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'ConnectTimeout=5',
                       'ProxyCommand=/usr/bin/nc -4 -b en6 -G 4 %h %p'):
            if option not in command_line:
                raise AssertionError('missing SSH guard: ' + option)
        if not any(option.startswith('UserKnownHostsFile=') for option in command_line):
            raise AssertionError('missing SSH pin')
        guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + BOOT +
                 '; test "$(wc -l </proc/mtd)" = 1; ')
        if not command_line[-1].startswith(guard):
            raise AssertionError('missing boot/MTD guard')
        command = command_line[-1][len(guard):]
        self.commands.append(command)
        if self.owner_busy and command.startswith('echo ') and command.endswith(' > ' + CLASSIFIER):
            return subprocess.CompletedProcess(command_line, 1, b'', b'Device or resource busy\n')
        if command == self.fail_command and self.commands.count(command) == self.fail_occurrence:
            return subprocess.CompletedProcess(command_line, 1, b'', b'injected command failure\n')
        result = ''
        if command.startswith('cat /sys/kernel/debug/gpio; '):
            result = 'ram-pon-tx-disable out hi\nstate DOWN\n' + self.classifier_status() + HEALTH
        elif command == 'cat ' + IPV6:
            result = self.ipv6 + '\n'
        elif command.startswith('test ! -d /sys/module/ct_pon_loopback; cat > '):
            if self.loaded or input != b'host-fixture-module':
                raise AssertionError('unexpected upload')
        elif command.startswith('test "$(sha256sum /tmp/ct_pon_loopback.ko '):
            self.loaded = True
        elif command == 'rmmod ct_pon_loopback':
            if self.prepared or self.routed or self.cover or self.classified or self.tuple_active:
                raise AssertionError('module unloaded before withdrawal/restoration')
            self.loaded = False
        elif command.startswith('echo '):
            parts = shlex.split(command)
            if len(parts) != 4 or parts[2] != '>':
                raise AssertionError('expected one write per command')
            value, destination = parts[1], parts[3]
            if destination == IPV6:
                self.ipv6 = value
            elif destination == CLASSIFIER:
                if value in ('cover 0', 'cover 1'):
                    self.cover = True
                    self.cover_slot = int(value.split()[1])
                elif value.startswith(('tuple ', 'set ')):
                    operation, slot, service = value.split()
                    if operation == 'tuple' and not self.cover:
                        raise AssertionError('consumer installed before cover')
                    if value.startswith('tuple ') and self.tuple_active:
                        raise AssertionError('tuple reinstalled before release')
                    self.classified = True
                    self.services[int(slot)] = int(service, 0)
                    self.tuple_active = value.startswith('tuple ')
                    self.routed = False
                elif value == 'route':
                    if not self.cover:
                        raise AssertionError('route enabled without cover')
                    self.routed = True
                elif value in ('clear 0', 'clear 1'):
                    if int(value.split()[1]) == self.cover_slot:
                        self.cover = False
                    else:
                        self.services.pop(int(value.split()[1]), None)
                        self.classified = bool(self.services)
                        self.tuple_active = False
                    self.routed = False
                elif value == 'off':
                    self.routed = self.cover = self.classified = self.tuple_active = False
                    self.services.clear()
                else:
                    raise AssertionError('unexpected classifier command: ' + value)
            elif destination == PROBE + 'command':
                if value == 'prepare':
                    self.prepared = True
                elif value == 'restore':
                    if self.routed or self.cover or self.classified:
                        raise AssertionError('restored before classifier withdrawal')
                    self.prepared = False
                elif value.startswith('send '):
                    if not self.loaded or not self.prepared:
                        raise AssertionError('send before module preparation')
                    fields = value.split()
                    packet = (int(fields[1]), fields[2] if len(fields) > 2 else 'ipv4',
                              int(fields[3]) if len(fields) > 3 else 0)
                    ring = 0
                    for slot in range(2):
                        if self.cover and self.cover_slot == slot:
                            ring = 2 + 2 * slot
                            break
                        if (slot in self.services and packet[0] == self.services[slot] and
                            packet[1] in ('ipv4', 'ipv6', 'fragment') and
                            (not self.tuple_active or packet[2] == 0)):
                            ring = 2 + 2 * slot
                            break
                    ring = self.ring_overrides.get(len(self.sent), ring)
                    self.sent.append(packet)
                    self.heads[ring] += 1
                else:
                    raise AssertionError('unexpected module command: ' + value)
            else:
                raise AssertionError('unexpected write destination: ' + destination)
        elif command.startswith('cat ' + PROBE + 'status'):
            result = self.status()
            if 'cat ' + CLASSIFIER in command:
                result += self.classifier_status()
            if 'cat ' + CONFIG in command:
                result += HEALTH
            if 'cat ' + POLICY in command and self.corrupt:
                result = self.corrupt(len(self.sent) - 1, result)
        elif command == 'cat ' + CLASSIFIER + '; cat ' + CONFIG:
            result = self.classifier_status() + HEALTH
        elif command.startswith('cat ' + CONFIG + '; cat ' + CLASSIFIER):
            result = self.classifier_status() + HEALTH
        else:
            raise AssertionError('unexpected remote command: ' + command)
        return subprocess.CompletedProcess(command_line, 0, result.encode(), b'')


class LoopbackRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='loopback-runner-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.module = self.root / 'module.ko'
        self.module.write_bytes(b'host-fixture-module')
        self.sha256 = hashlib.sha256(self.module.read_bytes()).hexdigest()
        self.invocations = 0

    def invoke(self, board, options=None):
        self.invocations += 1
        self.output = self.root / ('evidence-' + str(self.invocations))
        args = ['--pin', str(self.root / 'known-hosts'), '--boot', BOOT,
                '--module', str(self.module), '--sha256', self.sha256,
                '--output', str(self.output)]
        if options is None:
            options = EXACT_OPTIONS
        with mock.patch.object(sys, 'argv', [str(RUNNER_PATH)] + args + options), \
                mock.patch.object(RUNNER.subprocess, 'run', side_effect=board.run), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            RUNNER.main()
        return json.loads((self.output / 'report.json').read_text()) if (self.output / 'report.json').exists() else None

    def assert_restored(self, board):
        self.assertFalse(board.loaded)
        self.assertFalse(board.prepared)
        self.assertFalse(board.routed)
        self.assertFalse(board.cover)
        self.assertFalse(board.classified)
        self.assertFalse(board.tuple_active)
        self.assertEqual(board.ipv6, '0')
        withdrawal = board.commands.index('echo off > ' + CLASSIFIER)
        restoration = board.commands.index('echo restore > ' + PROBE + 'command')
        unload = board.commands.index('rmmod ct_pon_loopback')
        ipv6_restore = board.commands.index('echo 0 > ' + IPV6)
        self.assertLess(withdrawal, restoration)
        self.assertLess(restoration, unload)
        self.assertLess(unload, ipv6_restore)
        self.assertTrue(json.loads((self.output / 'report.json').read_text())['registers_restored'])

    def test_exact_tuple_twenty_packets(self):
        board = BoardFixture()
        report = self.invoke(board)
        self.assertTrue(report['exact_tuple'])
        self.assertTrue(report['commands_completed'])
        self.assertTrue(report['numbered_packets_returned'])
        self.assertTrue(report['service_preserved'])
        self.assertTrue(report['tuple_pool_released'])
        self.assertEqual(len(board.sent), 20)
        self.assertEqual(set(board.sent), {(service, family, variant)
                                          for service in (0x2134, 0xa134)
                                          for family in ('ipv4', 'ipv6') for variant in range(5)})
        self.assertEqual([item['expected_ring'] for item in report['observations']],
                         [2] + [4] * 9 + [2] + [4] * 9)
        self.assertEqual([item['changed_rings'] for item in report['observations']],
                         [[2]] + [[4]] * 9 + [[2]] + [[4]] * 9)
        self.assertIn("echo 'tuple 0 0x2134' > " + CLASSIFIER, board.commands)
        self.assertNotIn("echo 'set 0 0x2134' > " + CLASSIFIER, board.commands)
        self.assert_restored(board)

    def test_default_nonzero_three_packets(self):
        board = BoardFixture(exact=False)
        report = self.invoke(board, ['--run', '--special-tag'])
        self.assertEqual(board.sent, [(0x2134, 'ipv4', 0), (0xa134, 'ipv4', 0), (0x2134, 'ipv4', 0)])
        self.assertEqual([item['changed_rings'] for item in report['observations']], [[2], [4], [2]])
        self.assertFalse(report['service_zero'])
        self.assertEqual((report['service_a'], report['service_b']), (0x2134, 0xa134))
        self.assertIn("echo 'set 0 0x2134' > " + CLASSIFIER, board.commands)
        self.assertIn("echo 'set 1 0xa134' > " + CLASSIFIER, board.commands)
        self.assertTrue(report['service_preserved'])
        self.assert_restored(board)

    def test_service_zero_both_families_aba(self):
        board = BoardFixture(exact=False)
        report = self.invoke(board, ZERO_OPTIONS)
        self.assertTrue(report['service_zero'])
        self.assertEqual((report['service_a'], report['service_b']), (0, 0xa134))
        self.assertTrue(report['service_preserved'])
        self.assertTrue(report['numbered_packets_returned'])
        self.assertEqual(board.sent, [(service, kind, 0) for kind in ('ipv4', 'ipv6')
                                     for service in (0, 0xa134, 0)])
        self.assertEqual([item['expected_ring'] for item in report['observations']], [2, 4, 2] * 2)
        self.assertIn("echo 'set 0 0' > " + CLASSIFIER, board.commands)
        self.assertNotIn("echo 'set 0 0x2134' > " + CLASSIFIER, board.commands)
        self.assertNotIn("echo 'set 1 0' > " + CLASSIFIER, board.commands)
        for item in report['observations']:
            self.assertIn('active=0f', item['state'])
            self.assertIn('service0=0 service1=0', item['state'])
            self.assertIn('cover=02', item['state'])
        self.assert_restored(board)

    def test_service_zero_wide_withdrawal_both_families(self):
        board = BoardFixture(exact=False)
        report = self.invoke(board, ZERO_OPTIONS + ['--withdraw-cycle'])
        expected = [2, 4, 2] * 2 + [4, 4, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0]
        self.assertEqual(len(board.sent), 18)
        self.assertEqual([item['expected_ring'] for item in report['observations']], expected)
        self.assertEqual([item['changed_rings'] for item in report['observations']], [[ring] for ring in expected])
        self.assertEqual(board.sent[6:], [(service, kind, 0) for service in (0, 0, 0, 0xa134, 0, 0xa134)
                                         for kind in ('ipv4', 'ipv6')])
        self.assertEqual([item['transitions'] for item in report['observations'][6:]],
                         [['clear 0', 'route'], [], ['set 0 0', 'route'], [],
                          ['clear 1'], [], [], [], ['clear 0'], [], [], []])
        for packet, active, cover in ((6, '0c', '02'), (8, '0f', '02'), (10, '03', '00'), (14, '00', '00')):
            state = (self.output / f'send-{packet}-transition-0-state.stdout').read_text()
            self.assertIn('active=' + active, state)
            self.assertIn('cover=' + cover, state)
            self.assertIn('service0=0 service1=0', state)
        self.assert_restored(board)

    def test_service_zero_existing_matrices(self):
        for options, count, rings in (
            (['--packet-matrix'], 14, [2, 4, 2, 4, 4, 4, 4, 4, 4, 4, 2, 4, 4, 4]),
            (['--tuple-variants'], 20, [2, 4] * 10),
            (['--tuple-variants', '--exact-tuple'], 20, [2] + [4] * 9 + [2] + [4] * 9),
            (['--tuple-variants', '--exact-tuple', '--withdraw-cycle'], 28,
             [2] + [4] * 9 + [2] + [4] * 9 + [4, 2, 2, 2, 0, 0, 0, 0]),
        ):
            with self.subTest(options=options):
                board = BoardFixture()
                report = self.invoke(board, ZERO_OPTIONS + options)
                self.assertEqual(len(board.sent), count)
                self.assertEqual({packet[0] for packet in board.sent}, {0, 0xa134})
                self.assertEqual([item['expected_ring'] for item in report['observations']], rings)
                self.assertEqual([item['changed_rings'] for item in report['observations']],
                                 [[ring] for ring in rings])
                self.assertEqual(report['exact_tuple'], '--exact-tuple' in options)
                self.assertTrue(report['service_preserved'])
                if '--exact-tuple' in options:
                    self.assertIn("echo 'tuple 0 0' > " + CLASSIFIER, board.commands)
                    self.assertNotIn("echo 'set 0 0' > " + CLASSIFIER, board.commands)
                if '--withdraw-cycle' in options:
                    self.assertEqual(report['observations'][21]['transitions'], ['tuple 0 0', 'route'])
                    for packet in range(22, 26):
                        self.assertIn('tuple=1 pool=00003fff pool_pending=0 leases=2',
                                      report['observations'][packet]['state'])
                self.assert_restored(board)

    def test_service_zero_wrong_rings_stop_immediately(self):
        matrices = [([], [2, 4, 2] * 2),
                    (['--withdraw-cycle'], [2, 4, 2] * 2 + [4, 4, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0]),
                    (['--tuple-variants', '--exact-tuple', '--withdraw-cycle'],
                     [2] + [4] * 9 + [2] + [4] * 9 + [4, 2, 2, 2, 0, 0, 0, 0])]
        for options, rings in matrices:
            for index, ring in enumerate(rings):
                with self.subTest(options=options, packet=index):
                    board = BoardFixture(ring_overrides={index: 4 if ring != 4 else 2})
                    with self.assertRaisesRegex(AssertionError, 'expected RX'):
                        self.invoke(board, ZERO_OPTIONS + options)
                    self.assertEqual(len(board.sent), index + 1)
                    self.assert_restored(board)

    def test_service_zero_packet_and_classifier_mismatches(self):
        mutations = [
            ('rx_msg0=00000000', 'rx_msg0=00004000', 0),
            ('rx_msg0=284d0000', 'rx_msg0=00000000', 1),
            ('rx_msg1=00400000', 'rx_msg1=00200000', 0),
            ('rx_sequence=1 ', 'rx_sequence=0 ', 0),
            ('received=1 ', 'received=0 ', 0),
            ('tx_kind=ipv4 ', 'tx_kind=ipv6 ', 0),
            ('rx_kind=ipv6 ', 'rx_kind=ipv4 ', 3),
            ('active=0f', 'active=0c', 0),
            ('cover=02', 'cover=03', 0),
            ('service0=0 ', 'service0=8500 ', 0),
            ('ppe=0 ', 'ppe=1 ', 0),
            ('routed=1', 'routed=0', 0),
            ('pool_pending=0', 'pool_pending=1', 0),
            ('ct_cpu_fallback: 0 ', 'ct_cpu_fallback: 1 ', 0),
            ('allowed=1 failed=0', 'allowed=0 failed=0', 0),
        ]
        for original, replacement, packet in mutations:
            with self.subTest(field=original, packet=packet):
                board = BoardFixture(corrupt=lambda index, state: state.replace(original, replacement)
                                     if index == packet else state)
                with self.assertRaises(AssertionError):
                    self.invoke(board, ZERO_OPTIONS)
                self.assertEqual(len(board.sent), packet + 1)
                self.assert_restored(board)

    def test_service_zero_state_checked_before_next_packet(self):
        for command, occurrence, packet_count in (('set 0 0', 1, 0), ('clear 0', 1, 6),
                                                 ('set 0 0', 2, 8), ('clear 1', 1, 10),
                                                 ('clear 0', 2, 14)):
            with self.subTest(command=command, occurrence=occurrence):
                board = BoardFixture()
                original_status = board.classifier_status
                target = 'echo ' + shlex.quote(command) + ' > ' + CLASSIFIER

                def wrong_state():
                    state = original_status()
                    if board.commands.count(target) == occurrence and len(board.sent) == packet_count:
                        if board.commands[-1] == 'cat ' + CLASSIFIER + '; cat ' + CONFIG:
                            return state.replace('service0=0', 'service0=8500')
                    return state

                board.classifier_status = wrong_state
                with self.assertRaisesRegex(AssertionError, 'service0 classifier state mismatch'):
                    self.invoke(board, ZERO_OPTIONS + ['--withdraw-cycle'])
                self.assertEqual(len(board.sent), packet_count)
                self.assert_restored(board)

    def test_service_zero_command_failures_and_retention(self):
        for value, destination, occurrence, count in (
            ('set 0 0', CLASSIFIER, 1, 0), ('send 0 ipv4', PROBE + 'command', 1, 0),
            ('send 0 ipv6', PROBE + 'command', 1, 3), ('clear 0', CLASSIFIER, 1, 6),
            ('set 0 0', CLASSIFIER, 2, 8), ('clear 1', CLASSIFIER, 1, 10),
        ):
            with self.subTest(value=value, occurrence=occurrence):
                board = BoardFixture(fail_command='echo ' + shlex.quote(value) + ' > ' + destination,
                                     fail_occurrence=occurrence)
                with self.assertRaises((subprocess.CalledProcessError, RuntimeError)):
                    self.invoke(board, ZERO_OPTIONS + ['--withdraw-cycle'])
                self.assertEqual(len(board.sent), count)
                self.assert_restored(board)
        for value, destination in (('off', CLASSIFIER), ('restore', PROBE + 'command')):
            with self.subTest(cleanup=value):
                board = BoardFixture(fail_command='echo ' + value + ' > ' + destination)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke(board, ZERO_OPTIONS + ['--withdraw-cycle'])
                self.assertTrue(board.loaded)
                self.assertTrue(board.prepared)
                self.assertEqual(board.ipv6, '1')
                self.assertNotIn('rmmod ct_pon_loopback', board.commands)
                self.assertFalse((self.output / 'report.json').exists())
                label = 'classifier-off' if value == 'off' else 'restore'
                self.assertEqual(json.loads((self.output / (label + '.status.json')).read_text())['returncode'], 1)

    def test_service_zero_owner_busy_retains_module(self):
        board = BoardFixture()
        board.owner_busy = True
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(board, ZERO_OPTIONS)
        self.assertTrue(board.loaded)
        self.assertTrue(board.prepared)
        self.assertEqual(board.sent, [])
        self.assertNotIn('echo restore > ' + PROBE + 'command', board.commands)
        self.assertNotIn('rmmod ct_pon_loopback', board.commands)
        self.assertIn('Device or resource busy', (self.output / 'cover.stderr').read_text())

    def test_service_zero_preflight_and_argument_guards(self):
        board = BoardFixture()
        self.assertIsNone(self.invoke(board, [option for option in ZERO_OPTIONS if option != '--run']))
        self.assertEqual(len(board.commands), 1)
        self.assertEqual(board.sent, [])
        for options in (['--service-zero'], ['--service-zero', '--special-tag'],
                        ['--service-zero', '--cover-slot', '1'],
                        ['--service-zero', '--special-tag', '--cover-slot', '0'],
                        ZERO_OPTIONS + ['--sif-sweep']):
            with self.subTest(options=options):
                board = BoardFixture()
                with self.assertRaises(SystemExit) as error:
                    self.invoke(board, options)
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(board.commands, [])
        for original, replacement in (('ppe=0', 'ppe=1'), ('pool=00000000', 'pool=00000001'),
                                      ('pending=0', 'pending=1'), ('active=00', 'active=03')):
            with self.subTest(preflight=original):
                board = BoardFixture()
                original_status = board.classifier_status
                board.classifier_status = lambda: original_status().replace(original, replacement)
                with self.assertRaises(AssertionError):
                    self.invoke(board, ZERO_OPTIONS)
                self.assertEqual(len(board.commands), 1)
                self.assertFalse(board.loaded)

    def test_wide_service_regression(self):
        board = BoardFixture(exact=False)
        report = self.invoke(board, ['--run', '--special-tag', '--cover-slot', '1',
                                     '--tuple-variants', '--require-native'])
        self.assertFalse(report['exact_tuple'])
        self.assertEqual([item['changed_rings'] for item in report['observations']], [[2], [4]] * 10)
        self.assertEqual([item['expected_ring'] for item in report['observations']], [2, 4] * 10)
        self.assertIn("echo 'set 0 0x2134' > " + CLASSIFIER, board.commands)
        self.assertNotIn("echo 'tuple 0 0x2134' > " + CLASSIFIER, board.commands)
        self.assert_restored(board)

    def test_exact_tuple_withdrawal_reinstall_matrix(self):
        board = BoardFixture()
        report = self.invoke(board, EXACT_OPTIONS + ['--withdraw-cycle'])
        self.assertTrue(report['withdraw_cycle'])
        self.assertTrue(report['commands_completed'])
        self.assertTrue(report['numbered_packets_returned'])
        self.assertTrue(report['service_preserved'])
        expected_rings = [2] + [4] * 9 + [2] + [4] * 9 + [4, 2, 2, 2, 0, 0, 0, 0]
        self.assertEqual(len(board.sent), 28)
        self.assertEqual(board.sent[20:], [(0x2134, 'ipv4', 0)] * 3 +
                         [(0x2134, 'ipv6', 0), (0xa134, 'ipv4', 0),
                          (0x2134, 'ipv6', 1), (0x2134, 'ipv4', 0), (0x2134, 'ipv6', 0)])
        self.assertEqual([item['expected_ring'] for item in report['observations']], expected_rings)
        self.assertEqual([item['changed_rings'] for item in report['observations']],
                         [[ring] for ring in expected_rings])
        self.assertEqual([item['transitions'] for item in report['observations'][20:]],
                         [['clear 0', 'route'], ['tuple 0 0x2134', 'route'],
                          ['clear 1'], [], [], [], ['clear 0'], []])
        for packet_index, pool in ((20, board.pool_clean),
                                   (21, 'tuple=1 pool=00003fff pool_pending=0 leases=2'),
                                   (22, 'tuple=1 pool=00003fff pool_pending=0 leases=2'),
                                   (26, board.pool_clean)):
            state = (self.output / f'send-{packet_index}-transition-0-state.stdout').read_text()
            self.assertIn(pool, state)
            self.assertIn(pool, report['observations'][packet_index]['state'])
        for packet_index in range(22, 26):
            self.assertIn('tuple=1 pool=00003fff pool_pending=0 leases=2',
                          report['observations'][packet_index]['state'])
            self.assertIn('routed=0', report['observations'][packet_index]['state'])
        self.assertIn(board.pool_clean, report['observations'][27]['state'])
        self.assert_restored(board)

    def test_wide_service_eight_packet_withdrawal(self):
        for cover_slot, expected_rings in ((0, [2, 2, 2, 2, 2, 2, 0, 0]),
                                           (1, [2, 4, 2, 4, 4, 2, 0, 0])):
            with self.subTest(cover_slot=cover_slot):
                board = BoardFixture(exact=False)
                report = self.invoke(board, ['--run', '--special-tag', '--cover-slot', str(cover_slot),
                                             '--withdraw-cycle', '--require-native'])
                self.assertEqual(len(board.sent), 8)
                self.assertEqual([item['expected_ring'] for item in report['observations']], expected_rings)
                self.assertEqual([item['changed_rings'] for item in report['observations']],
                                 [[ring] for ring in expected_rings])
                self.assert_restored(board)

    def test_each_wrong_withdrawal_destination_fails_and_restores(self):
        for packet_index, wrong_ring in ((20, 2), (21, 4), (22, 0), (23, 0),
                                        (24, 2), (25, 2), (26, 4), (27, 2)):
            with self.subTest(packet=packet_index):
                board = BoardFixture(ring_overrides={packet_index: wrong_ring})
                with self.assertRaisesRegex(AssertionError, 'expected RX'):
                    self.invoke(board, EXACT_OPTIONS + ['--withdraw-cycle'])
                self.assertEqual(len(board.sent), packet_index + 1)
                self.assert_restored(board)

    def test_withdrawal_pool_failures_stop_before_next_step(self):
        mutations = [
            ('clear 0', 1, 'tuple=0', 'tuple=1', 20),
            ('clear 0', 1, 'pool=00000000', 'pool=00000001', 20),
            ('clear 0', 1, 'pool_pending=0', 'pool_pending=1', 20),
            ('clear 0', 1, 'leases=0', 'leases=1', 20),
            ('tuple 0 0x2134', 2, 'pool=00003fff', 'pool=00001fff', 21),
            ('tuple 0 0x2134', 2, 'leases=2', 'leases=1', 21),
            ('tuple 0 0x2134', 2, 'pool_pending=0', 'pool_pending=1', 21),
            ('clear 1', 1, 'pool=00003fff', 'pool=00000000', 22),
            ('clear 1', 1, 'pool=00003fff', 'pool=00007ffe', 22),
            ('clear 1', 1, 'leases=2', 'leases=0', 22),
            ('clear 0', 2, 'pool=00000000', 'pool=00000001', 26),
        ]
        for command, occurrence, original, replacement, packet_count in mutations:
            with self.subTest(command=command, occurrence=occurrence, field=original):
                board = BoardFixture()
                original_status = board.classifier_status
                target = 'echo ' + shlex.quote(command) + ' > ' + CLASSIFIER

                def corrupt_transition():
                    state = original_status()
                    if board.commands.count(target) == occurrence and board.commands[-2] == target:
                        return state.replace(original, replacement)
                    return state

                board.classifier_status = corrupt_transition
                with self.assertRaisesRegex(AssertionError, 'tuple pool'):
                    self.invoke(board, EXACT_OPTIONS + ['--withdraw-cycle'])
                self.assertEqual(len(board.sent), packet_count)
                command_index = len(board.commands) - 1 - board.commands[::-1].index(target)
                self.assertEqual(board.commands[command_index + 2], 'echo off > ' + CLASSIFIER)
                self.assert_restored(board)

    def test_withdrawal_transition_command_failures_restore(self):
        failures = [('clear 0', 1, 20), ('route', 2, 20), ('tuple 0 0x2134', 2, 21),
                    ('route', 3, 21), ('clear 1', 1, 22), ('clear 0', 2, 26)]
        for command, occurrence, packet_count in failures:
            with self.subTest(command=command, occurrence=occurrence):
                board = BoardFixture(fail_command='echo ' + shlex.quote(command) + ' > ' + CLASSIFIER,
                                     fail_occurrence=occurrence)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke(board, EXACT_OPTIONS + ['--withdraw-cycle'])
                self.assertEqual(len(board.sent), packet_count)
                self.assert_restored(board)

    def test_failed_matrix_restoration_retains_module(self):
        for command in ('echo off > ' + CLASSIFIER, 'echo restore > ' + PROBE + 'command'):
            with self.subTest(command=command):
                board = BoardFixture(fail_command=command)
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke(board, EXACT_OPTIONS + ['--withdraw-cycle'])
                self.assertEqual(len(board.sent), 28)
                self.assertTrue(board.loaded)
                self.assertTrue(board.prepared)
                self.assertNotIn('rmmod ct_pon_loopback', board.commands)
                self.assertFalse((self.output / 'report.json').exists())

    def test_each_wrong_tuple_destination_fails_and_restores(self):
        for packet_index in range(20):
            with self.subTest(packet=packet_index):
                board = BoardFixture(ring_overrides={packet_index: 4 if packet_index in (0, 10) else 2})
                with self.assertRaisesRegex(AssertionError, 'expected RX'):
                    self.invoke(board)
                self.assertEqual(len(board.sent), packet_index + 1)
                report = json.loads((self.output / 'report.json').read_text())
                self.assertNotIn('commands_completed', report)
                self.assertEqual(len(report['observations']), packet_index + 1)
                self.assert_restored(board)

    def test_packet_identity_and_health_failures_restore(self):
        mutations = [
            ('received=1 ', 'received=0 '),
            ('rx_sequence=1 ', 'rx_sequence=0 '),
            ('tx_variant=0\n', 'tx_variant=1\n'),
            ('tx_kind=ipv4 ', 'tx_kind=ipv6 '),
            ('rx_kind=ipv4 ', 'rx_kind=ipv6 '),
            ('routed=1\n', 'routed=0\n'),
            ('ct_cpu_fallback: 0 ', 'ct_cpu_fallback: 1 '),
            ('allowed=1 failed=0', 'allowed=0 failed=0'),
            ('allowed=1 failed=0', 'allowed=1 failed=1'),
        ]
        for original, replacement in mutations:
            with self.subTest(field=original):
                board = BoardFixture(corrupt=lambda index, status: status.replace(original, replacement))
                with self.assertRaises(AssertionError):
                    self.invoke(board)
                self.assertEqual(len(board.sent), 1)
                self.assert_restored(board)

    def test_service_and_source_mismatches_fail(self):
        for original, replacement in [('rx_msg0=084d0000', 'rx_msg0=284d0000'),
                                      ('rx_msg1=00400000', 'rx_msg1=00200000')]:
            with self.subTest(field=original):
                board = BoardFixture(corrupt=lambda index, status: status.replace(original, replacement))
                with self.assertRaisesRegex(AssertionError, 'special tag service mismatch'):
                    self.invoke(board)
                self.assertFalse(json.loads((self.output / 'report.json').read_text())['service_preserved'])
                self.assert_restored(board)

    def test_command_failure_withdraws_and_restores(self):
        for command in ("echo 'tuple 0 0x2134' > " + CLASSIFIER,
                        'echo route > ' + CLASSIFIER,
                        "echo 'send 8500 ipv4 0' > " + PROBE + 'command'):
            with self.subTest(command=command):
                board = BoardFixture(fail_command=command)
                with self.assertRaises((subprocess.CalledProcessError, RuntimeError)):
                    self.invoke(board)
                self.assert_restored(board)

    def test_failed_withdrawal_retains_module(self):
        board = BoardFixture(fail_command='echo off > ' + CLASSIFIER)
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke(board)
        self.assertTrue(board.loaded)
        self.assertTrue(board.prepared)
        self.assertNotIn('echo restore > ' + PROBE + 'command', board.commands)
        self.assertNotIn('rmmod ct_pon_loopback', board.commands)

    def test_preflight_does_not_write(self):
        board = BoardFixture()
        report = self.invoke(board, ['--special-tag', '--cover-slot', '1',
                                     '--tuple-variants', '--exact-tuple', '--require-native'])
        self.assertIsNone(report)
        self.assertEqual(len(board.commands), 1)
        self.assertTrue(board.commands[0].startswith('cat /sys/kernel/debug/gpio; '))
        self.assertEqual(board.sent, [])

    def test_invalid_options_stop_before_ssh(self):
        options = [
            ['--exact-tuple'],
            ['--exact-tuple', '--special-tag', '--cover-slot', '1'],
            ['--exact-tuple', '--tuple-variants', '--special-tag'],
            ['--exact-tuple', '--tuple-variants', '--special-tag', '--cover-slot', '0'],
            ['--exact-tuple', '--tuple-variants', '--cover-slot', '1'],
            ['--tuple-variants', '--special-tag', '--cover-slot', '1', '--withdraw-cycle'],
        ]
        options += [['--exact-tuple', '--tuple-variants', '--special-tag', '--cover-slot', '1', experiment]
                    for experiment in ('--packet-matrix', '--sif-sweep')]
        for combination in options:
            with self.subTest(options=combination):
                board = BoardFixture()
                with self.assertRaises(SystemExit) as error:
                    self.invoke(board, combination)
                self.assertEqual(error.exception.code, 2)
                self.assertEqual(board.commands, [])
                self.assertFalse(self.output.exists())

    def test_dirty_tuple_pool_rejects_preflight(self):
        for field in ('tuple=1', 'pool=00000001', 'pool_pending=1', 'leases=1'):
            with self.subTest(field=field):
                board = BoardFixture()
                original = next(part for part in board.pool_clean.split() if part.split('=')[0] == field.split('=')[0])
                board.pool_clean = board.pool_clean.replace(original, field)
                with self.assertRaisesRegex(AssertionError, 'tuple pool is not idle'):
                    self.invoke(board)
                self.assertEqual(len(board.commands), 1)

    def test_failed_tuple_release_retains_module(self):
        board = BoardFixture()
        original_status = board.classifier_status

        def status_after_withdrawal():
            result = original_status()
            if 'echo off > ' + CLASSIFIER in board.commands:
                result = result.replace('pool=00000000', 'pool=00000001')
            return result

        board.classifier_status = status_after_withdrawal
        with self.assertRaisesRegex(AssertionError, 'tuple pool was not released'):
            self.invoke(board)
        self.assertTrue(board.loaded)
        self.assertNotIn('rmmod ct_pon_loopback', board.commands)

    def test_optimized_python_is_rejected(self):
        result = subprocess.run([sys.executable, '-B', '-O', str(RUNNER_PATH)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertIn('Run without -O', result.stderr)


if __name__ == '__main__':
    unittest.main()
