#!/usr/bin/env python3
"""Exercise BND orchestration with real session, ER and UDP validators."""
import errno
import struct
import unittest
from unittest import mock

import lan_udp_receiver as udp
import run_npu_bound as bound
import run_npu_loopback as loopback
from test_lan_udp_receiver import DatagramQueue
from test_run_npu_loopback import BoardFixture, render


HOST_IP = '192.168.1.120'
HOST_MAC = '00:e0:4c:68:00:30'
COOKIE = 123
ROW = 0x0458
ORIGINAL = '192.0.2.1:49152->192.0.2.2:49153'
TRANSLATED = f'192.0.2.1:49152->{HOST_IP}:49153'
PEER = ('192.0.2.1', 49152)
SAMPLES = (('ipv4', 0), ('ipv4', 1), ('ipv4', 2), ('ipv4', 3),
           ('ipv4', 4), ('ipv6', 0), ('ipv4', None), ('ipv4', 'alt'), ('ipv4', 0))
LEARNED = ((ROW, ORIGINAL),)


def datagram(sequence, cookie=COOKIE):
    return struct.pack('!5I', 0x4354504e, sequence, cookie, 0, 128) + bytes(66)


class BoundPeer:
    def __init__(self, service=0):
        self.service = service
        self.board = BoardFixture()
        self.board.prepared = self.board.owner = self.board.ring = True
        self.board.auth_mode = self.board.learn_mode = True
        self.board.service = service
        self.board.alt_service = service ^ 1
        self.board.epoch = 7
        for kind, variant in (('ipv4', 0), ('ipv4', 1), ('ipv4', 2), ('ipv4', 3),
                              ('ipv4', 4), ('ipv6', 0), ('ipv4', None), ('ipv4', 0)) * 2:
            matched = kind == 'ipv4' and variant == 0
            self.board.sent.append(dict(kind=kind, path='auth' if matched else 'er',
                                        fixed=variant is not None, variant=variant or 0))
        self.board.consumed = 12
        self.board.last_er = (15, 'ipv4', service)
        self.initial_sequence = len(self.board.sent)
        self.queue = DatagramQueue()
        self.report = {}
        self.commands = []
        self.installed = False
        self.state_overrides = {}
        self.entry_row = ROW
        self.entry_state = 'BND'
        self.entry_original = ORIGINAL
        self.entry_new = TRANSLATED
        self.entry_copies = 1
        self.on_send = None
        self.on_diag = None
        self.on_probe = None
        self.install_error = None

    @property
    def sample_index(self):
        return len(self.board.sent) - self.initial_sequence

    def entries(self):
        entry = (f'{self.entry_row:05x} {self.entry_state} IPv4 5T '
                 f'orig={self.entry_original} new={self.entry_new} '
                 f'eth=d0:69:ff:1a:46:cc->{HOST_MAC} etype=0800 '
                 'data=007f0000 vlan=0,0 ib1=e1000047 ib2=0003e720 packets=0 bytes=0')
        return '\n'.join([entry] * self.entry_copies) + '\n'

    def diag(self):
        state = loopback.fields(self.board.diag())
        state.update(bound_mode='1', bound_hash=f'{ROW:04x}',
                     bound_service=str(self.service))
        state.update(self.state_overrides)
        if self.sample_index and self.on_diag:
            self.on_diag(self, state)
        return render(state)

    def probe(self, after=False):
        state = loopback.fields(self.board.probe())
        received = [packet for packet in self.board.sent if packet['path'] != 'lan']
        last_received = max(index for index, packet in enumerate(self.board.sent, 1)
                            if packet['path'] != 'lan')
        state.update(received=str(len(received)), rx_sequence=str(last_received),
                     rx_kind=received[-1]['kind'], rx_data='4', rx_delivered='4')
        if after and self.on_probe:
            self.on_probe(self, state)
        return render(state)

    def remote(self, label, command):
        if command == 'cat ' + loopback.DIAG:
            return self.diag()
        if command == 'cat ' + loopback.PROBE + 'status':
            return self.probe(after=label.endswith('-probe'))
        if command == 'cat /sys/kernel/debug/ppe/entries':
            return self.entries()
        raise AssertionError('unexpected read: ' + command)

    def write(self, label, path, command):
        self.commands.append(command)
        if path == loopback.DIAG:
            if self.install_error:
                raise self.install_error
            assert command == f'bind-lan1 {ROW} {HOST_IP} {HOST_MAC}'
            assert not self.installed and (ROW, ORIGINAL) in LEARNED
            self.installed = True
            self.board.epoch += 1
            self.board.consumed = 0
            self.board.last_er = None
            return
        assert self.installed and path == loopback.PROBE + 'command'
        words = command.split()
        kind = words[1]
        if words[0] == 'send-fixed':
            variant = int(words[2])
            assert words == ['send-fixed', kind, str(variant), 'tx' if (kind == 'ipv4' and variant == 0) else 'rx']
        elif words[0] == 'send-fixed-alt':
            variant = 'alt'
            assert words == ['send-fixed-alt', kind, '0', 'rx']
        else:
            variant = None
            assert words == ['send-current', 'ipv4']
        matched = kind == 'ipv4' and variant == 0
        self.board.sent.append(dict(kind=kind, path='lan' if matched else 'er',
                                    fixed=isinstance(variant, int),
                                    variant=variant if isinstance(variant, int) else 0))
        sequence = len(self.board.sent)
        if matched:
            self.queue.datagrams.append((datagram(sequence), PEER))
        else:
            self.board.consumed += 1
            self.board.last_er = (sequence, kind, self.service ^ 1 if variant == 'alt' else self.service)
        if self.on_send:
            self.on_send(self, matched, sequence)

    def run(self):
        with mock.patch.object(udp, 'open_receiver', return_value=self.queue):
            bound.run_bound_matrix(self.remote, self.write, loopback.DIAG, loopback.PROBE,
                                   loopback.fields, loopback.check_session, loopback.check_packet,
                                   self.service, ROW, HOST_IP, HOST_MAC, COOKIE, self.report)
        return self.report['bound_observations']


class BoundTests(unittest.TestCase):
    def reject(self, peer, message, exception=ValueError):
        with self.assertRaisesRegex(exception, message) as caught:
            peer.run()
        self.assertTrue(peer.queue.closed)
        return caught.exception

    def test_real_five_digit_learned_row_and_forward_matrix(self):
        for service in (0, 0x8000):
            with self.subTest(service=service):
                peer = BoundPeer(service)
                observations = peer.run()
                self.assertEqual(len(observations), 9)
                self.assertEqual(peer.commands[0], f'bind-lan1 {ROW} {HOST_IP} {HOST_MAC}')
                self.assertEqual([sample['sequence'] for sample in observations], list(range(17, 26)))
                self.assertEqual([(sample['kind'], sample['variant']) for sample in observations], list(SAMPLES))
                self.assertEqual([int(sample['diag']['consumed']) for sample in observations],
                                 [0, 1, 2, 3, 4, 5, 6, 7, 7])
                self.assertEqual([sample['probe']['rx_sequence'] for sample in observations],
                                 ['16', '18', '19', '20', '21', '22', '23', '24', '24'])
                self.assertEqual(len(peer.report['bound_final_entries']), 1)
                for sample in observations:
                    self.assertIsNone(sample['send_error'])
                    self.assertTrue(sample['receiver']['passed'])
                    self.assertEqual(sample['probe']['rx_data'], '4')
                    self.assertEqual(sample['probe']['rx_delivered'], '4')
                    if sample['matched']:
                        self.assertEqual(sample['receiver']['accepted'], [sample['sequence']])
                        captured = sample['receiver']['observations'][0]
                        self.assertEqual(captured['payload_hex'], datagram(sample['sequence']).hex())
                    else:
                        self.assertTrue(sample['receiver']['queue_empty'])
                self.assertTrue(peer.queue.closed)

    def test_installed_bound_identity(self):
        for name, value in (('bound_mode', '0'), ('bound_hash', '0459'),
                            ('bound_service', '32768')):
            with self.subTest(name=name):
                peer = BoundPeer()
                peer.state_overrides[name] = value
                self.reject(peer, 'bound session identity mismatch')
                self.assertEqual(peer.report['bound_observations'], [])

    def test_installed_production_session_checks(self):
        for name, value in (('owner', '0'), ('qualified', '1'), ('policy', '1'),
                            ('flow', '00002000'), ('next_row', '0'),
                            ('bank0_flow', '00000000'), ('bank0_next_row', '8192'), ('gate_epoch', '99')):
            with self.subTest(name=name):
                peer = BoundPeer()
                peer.state_overrides[name] = value
                self.reject(peer, 'diagnostic state|bank1 learning|PPE learning|transaction identity')

    def test_wrong_original_or_translated_tuple(self):
        for name, value in (('entry_original', '192.0.2.1:49153->192.0.2.2:49153'),
                            ('entry_new', '192.0.2.1:49152->192.168.1.121:49153'),
                            ('entry_new', '192.0.2.2:49152->192.168.1.120:49153'),
                            ('entry_new', '192.0.2.1:49152->192.168.1.120:49154')):
            with self.subTest(name=name, value=value):
                peer = BoundPeer()
                setattr(peer, name, value)
                self.reject(peer, 'bound row tuple mismatch')
                self.assertEqual(len(peer.commands), 1)

    def test_wrong_missing_duplicate_or_unbound_row(self):
        for name, value in (('entry_row', ROW + 1), ('entry_state', 'UNB'),
                            ('entry_state', 'FIN'), ('entry_copies', 0), ('entry_copies', 2)):
            with self.subTest(name=name, value=value):
                peer = BoundPeer()
                setattr(peer, name, value)
                self.reject(peer, 'bound row tuple mismatch')
                self.assertEqual(len(peer.commands), 1)

    def test_host_must_be_silent_for_every_mismatch_including_random_smac(self):
        for target in range(2, 9):
            with self.subTest(sample=target):
                peer = BoundPeer()

                def leak(current, matched, sequence):
                    if current.sample_index == target:
                        self.assertFalse(matched)
                        current.queue.datagrams.append((datagram(sequence), PEER))

                peer.on_send = leak
                error = self.reject(peer, 'unexpected datagram', udp.ReceiverError)
                sample = peer.report['bound_observations'][-1]
                self.assertIs(sample['receiver'], error.report)
                self.assertFalse(sample['matched'])
                self.assertEqual(sample['receiver']['unexpected']['captured_bytes'], 86)
                self.assertEqual(sample['receiver']['unexpected']['marker_hex'],
                                 datagram(sample['sequence'])[:20].hex())
                self.assertEqual(len(peer.report['bound_observations']), target)

    def test_forwarded_wrong_marker_source_length_and_duplicate_are_recorded(self):
        for fault in ('cookie', 'sequence', 'source', 'length', 'duplicate'):
            with self.subTest(fault=fault):
                peer = BoundPeer()

                def corrupt(current, matched, sequence):
                    if current.sample_index != 1:
                        return
                    payload, source = current.queue.datagrams.pop()
                    if fault == 'cookie':
                        payload = datagram(sequence, COOKIE + 1)
                    elif fault == 'sequence':
                        payload = datagram(sequence + 1)
                    elif fault == 'source':
                        source = ('192.0.2.2', 49152)
                    elif fault == 'length':
                        payload += b'x'
                    current.queue.datagrams.append((payload, source))
                    if fault == 'duplicate':
                        current.queue.datagrams.append((payload, source))

                peer.on_send = corrupt
                error = self.reject(peer, 'mismatch|unexpected datagram', udp.ReceiverError)
                sample = peer.report['bound_observations'][-1]
                self.assertIs(sample['receiver'], error.report)
                self.assertEqual(sample['receiver']['rejected'], 1)
                self.assertEqual(sample['receiver']['duplicates'], int(fault == 'duplicate'))

    def test_qdma_leaks_on_match_miss_and_final_match(self):
        for target in (1, 2, 8, 9):
            for counter in ('rx_data', 'rx_delivered'):
                with self.subTest(sample=target, counter=counter):
                    peer = BoundPeer()

                    def leak(current, packet):
                        if current.sample_index == target:
                            packet[counter] = str(int(packet[counter]) + 1)

                    peer.on_probe = leak
                    self.reject(peer, 'unexpectedly reached QDMA CPU receive')
                    self.assertEqual(len(peer.report['bound_observations']), target)
                    self.assertTrue(peer.report['bound_observations'][-1]['receiver']['passed'])

    def test_er_or_probe_receive_leaks_on_forwarded_packets(self):
        for target in (1, 9):
            for counter in ('packets', 'consumed', 'received'):
                with self.subTest(sample=target, counter=counter):
                    peer = BoundPeer()

                    def leak(current, values):
                        if current.sample_index == target:
                            values[counter] = str(int(values[counter]) + 1)

                    if counter == 'received':
                        peer.on_probe = leak
                    else:
                        peer.on_diag = leak
                    self.reject(peer, 'bound match unexpectedly reached host receive')

    def test_tx_completion_and_sequence_faults(self):
        for name, value in (('sequence', '16'), ('pending', '1'), ('error', '-5')):
            with self.subTest(name=name):
                peer = BoundPeer()
                peer.on_probe = lambda current, packet: packet.update({name: value})
                self.reject(peer, 'bound TX sequence or completion mismatch')

    def test_runtime_session_faults(self):
        for name, value in (('invalidated', '1'), ('auth_count', '0'), ('auth_inflight', '1'),
                            ('gate_fault', '1'), ('ring', '0'), ('auth_generation', '99')):
            with self.subTest(name=name):
                peer = BoundPeer()
                peer.on_diag = lambda current, state: state.update({name: value})
                self.reject(peer, 'diagnostic state|transaction identity')

    def test_real_er_descriptor_rejects_wrong_service_epoch_and_prefix(self):
        for target in (2, 6, 8):
            for index in (1, 2, 4, 5, 7, 9, 10, 13, 14):
                with self.subTest(sample=target, word=index):
                    peer = BoundPeer(service=0x8000)

                    def corrupt(current, state):
                        if current.sample_index == target:
                            words = state['er_desc'].split('/')
                            mask = 1 << 28 if index == 13 else 1
                            words[index] = f'{int(words[index], 16) ^ mask:08x}'
                            state['er_desc'] = '/'.join(words)

                    peer.on_diag = corrupt
                    self.reject(peer, 'ER identity mismatch|FE prefix mismatch')

    def test_real_er_frame_marker_and_producer_consumer_faults(self):
        for target in (2, 6):
            for fault in ('magic', 'sequence', 'kind', 'length', 'observed_produced', 'observed_consumed'):
                with self.subTest(sample=target, fault=fault):
                    peer = BoundPeer()

                    def corrupt(current, state):
                        if current.sample_index != target:
                            return
                        if fault.startswith('observed_'):
                            state[fault] = str(int(state[fault]) + 1)
                        else:
                            frame = bytearray.fromhex(state['er_frame'])
                            offset = 62 if target == 6 else 42
                            frame[offset + dict(magic=0, sequence=4, kind=12, length=16)[fault]] ^= 1
                            state['er_frame'] = frame.hex()

                    peer.on_diag = corrupt
                    self.reject(peer, 'ER packet marker|ER producer/consumer evidence mismatch')

    def test_udp_timeout_report_is_retained(self):
        peer = BoundPeer()
        peer.on_send = lambda current, matched, sequence: current.queue.datagrams.clear()
        error = self.reject(peer, 'timed out waiting', udp.ReceiverError)
        sample = peer.report['bound_observations'][-1]
        self.assertIs(sample['receiver'], error.report)
        self.assertTrue(sample['receiver']['timed_out'])
        self.assertEqual(sample['receiver']['accepted'], [])
        self.assertIsNone(sample['send_error'])
        self.assertEqual(sample['sequence'], 17)

    def test_send_error_keeps_diag_probe_and_receiver_result(self):
        for target in (1, 2):
            with self.subTest(sample=target):
                peer = BoundPeer()

                def fail(current, matched, sequence):
                    if current.sample_index == target:
                        raise OSError(errno.EIO, 'injected TX failure')

                peer.on_send = fail
                self.reject(peer, 'bound probe send failed.*injected TX failure')
                sample = peer.report['bound_observations'][-1]
                self.assertIn('injected TX failure', sample['send_error'])
                self.assertEqual(sample['probe']['sequence'], str(16 + target))
                self.assertEqual(sample['diag']['bound_hash'], '0458')
                self.assertTrue(sample['receiver']['passed'])

    def test_send_error_and_udp_timeout_are_both_retained(self):
        peer = BoundPeer()

        def fail(current, matched, sequence):
            current.queue.datagrams.clear()
            raise OSError(errno.EIO, 'injected TX failure')

        peer.on_send = fail
        self.reject(peer, 'timed out waiting', udp.ReceiverError)
        sample = peer.report['bound_observations'][-1]
        self.assertIn('injected TX failure', sample['send_error'])
        self.assertTrue(sample['receiver']['timed_out'])
        self.assertEqual(sample['probe']['sequence'], '17')

    def test_install_error_closes_receiver_before_sending(self):
        peer = BoundPeer()
        peer.install_error = OSError(errno.ESTALE, 'learned row changed')
        self.reject(peer, 'learned row changed', OSError)
        self.assertEqual(peer.report['bound_observations'], [])
        self.assertEqual(peer.sample_index, 0)

    def test_stale_udp_queue_prevents_install(self):
        peer = BoundPeer()
        peer.queue.datagrams.append((datagram(16), PEER))
        self.reject(peer, 'receive queue is not empty', udp.ReceiverError)
        self.assertEqual(peer.commands, [])
        self.assertEqual(peer.report['bound_observations'], [])


if __name__ == '__main__':
    unittest.main()
