#!/usr/bin/env python3
import contextlib
import errno
import io
import json
import socket
import struct
import unittest
from unittest import mock

import lan_udp_receiver as receiver


COOKIE = 0x10203040
PEER = ('192.0.2.1', 49152)


def packet(sequence=7, cookie=COOKIE):
    return struct.pack('!5I', 0x4354504E, sequence, cookie, 0, 128) + bytes(66)


class DatagramQueue:
    def __init__(self, datagrams=(), timeout=None):
        self.datagrams = list(datagrams)
        self.timeout = timeout
        self.timeouts = []
        self.closed = False

    def gettimeout(self):
        return self.timeout

    def settimeout(self, timeout):
        self.timeout = timeout
        self.timeouts.append(timeout)

    def recvfrom(self, size):
        if not self.datagrams:
            if self.timeout == 0:
                raise BlockingIOError(errno.EAGAIN, 'empty queue')
            raise socket.timeout()
        entry = self.datagrams.pop(0)
        if isinstance(entry, BaseException):
            raise entry
        payload, peer = entry
        return payload[:size], peer

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.close()


class DatagramTests(unittest.TestCase):
    def test_constants_and_exact_packet(self):
        self.assertEqual(receiver.DESTINATION_PORT, 49153)
        self.assertEqual((receiver.SOURCE_IP, receiver.SOURCE_PORT), PEER)
        self.assertEqual(receiver.PAYLOAD_BYTES, 86)
        self.assertEqual(receiver.MARKER_BYTES, 20)
        self.assertEqual(receiver.expected_marker(7, COOKIE), packet()[:20])
        result = receiver.validate_datagram(packet(), PEER, 7, COOKIE)
        self.assertEqual(result['sequence'], 7)
        self.assertEqual(result['cookie'], COOKIE)
        self.assertEqual(result['payload_hex'], packet().hex())

    def test_each_marker_bit_is_checked(self):
        for offset in range(20):
            for bit in range(8):
                payload = bytearray(packet())
                payload[offset] ^= 1 << bit
                with self.subTest(offset=offset, bit=bit), self.assertRaisesRegex(ValueError, 'marker mismatch'):
                    receiver.validate_datagram(payload, PEER, 7, COOKIE)

    def test_payload_lengths(self):
        for length in (*range(86), 87, 128, 2048, 65507):
            payload = (packet() + bytes(65507))[:length]
            with self.subTest(length=length), self.assertRaisesRegex(ValueError, 'length mismatch'):
                receiver.validate_datagram(payload, PEER, 7, COOKIE)

    def test_exact_source(self):
        for peer in (('192.0.2.2', 49152), ('192.0.2.1', 49153), ('192.0.2.1', '49152'),
                     ('::ffff:192.0.2.1', 49152), (), ('192.0.2.1', 49152, 0, 0), None):
            with self.subTest(peer=peer), self.assertRaisesRegex(ValueError, 'source mismatch'):
                receiver.validate_datagram(packet(), peer, 7, COOKIE)

    def test_zero_cookie_and_maximum_sequence(self):
        result = receiver.validate_datagram(packet(0xFFFFFFFF, 0), PEER, 0xFFFFFFFF, 0)
        self.assertEqual(result['cookie'], 0)
        self.assertEqual(result['sequence'], 0xFFFFFFFF)


class ReceiveTests(unittest.TestCase):
    def test_ordered_batch_and_empty_queue(self):
        queue = DatagramQueue([(packet(7), PEER), (packet(8), PEER)], timeout=2)
        result = receiver.receive_expected(queue, COOKIE, 7, count=2)
        self.assertTrue(result['passed'])
        self.assertTrue(result['queue_empty'])
        self.assertEqual(result['accepted'], [7, 8])
        self.assertEqual(result['rejected'], 0)
        self.assertEqual(result['duplicates'], 0)
        self.assertEqual(len(result['observations']), 2)
        self.assertEqual(queue.timeout, 2)
        self.assertIn(0, queue.timeouts)

    def test_wrong_packets_fail_before_later_good_packet(self):
        invalid = [(packet(8), PEER), (packet(7, COOKIE + 1), PEER), (b'', PEER),
                   (packet() + b'x', PEER), (packet(), ('192.0.2.2', 49152))]
        for datagram in invalid:
            queue = DatagramQueue([datagram, (packet(), PEER)], timeout=3)
            with self.subTest(datagram=datagram), self.assertRaises(receiver.ReceiverError) as caught:
                receiver.receive_expected(queue, COOKIE, 7)
            self.assertFalse(caught.exception.report['passed'])
            self.assertEqual(caught.exception.report['accepted'], [])
            self.assertEqual(caught.exception.report['rejected'], 1)
            self.assertEqual(len(queue.datagrams), 1)
            self.assertEqual(queue.timeout, 3)

    def test_duplicate_during_batch_fails(self):
        queue = DatagramQueue([(packet(), PEER), (packet(), PEER), (packet(8), PEER)])
        with self.assertRaises(receiver.ReceiverError) as caught:
            receiver.receive_expected(queue, COOKIE, 7, count=2)
        self.assertEqual(caught.exception.report['accepted'], [7])
        self.assertEqual(caught.exception.report['duplicates'], 1)
        self.assertFalse(caught.exception.report['passed'])

    def test_any_trailing_packet_fails_including_after_quiet_timeout(self):
        for settle in (0, 100):
            for tail, duplicate in (((packet(), PEER), 1), ((packet(8), PEER), 0),
                                    ((packet(), ('192.0.2.2', 49152)), 0), ((b'', PEER), 0)):
                queue = DatagramQueue([(packet(), PEER), tail])
                with self.subTest(settle=settle, tail=tail), self.assertRaises(receiver.ReceiverError) as caught:
                    receiver.receive_expected(queue, COOKIE, 7, settle_ms=settle)
                self.assertEqual(caught.exception.report['duplicates'], duplicate)
                self.assertEqual(caught.exception.report['rejected'], 1)
                self.assertFalse(caught.exception.report['queue_empty'])
        queue = DatagramQueue([(packet(), PEER), socket.timeout(), (packet(), PEER)])
        with self.assertRaises(receiver.ReceiverError) as caught:
            receiver.receive_expected(queue, COOKIE, 7)
        self.assertEqual(caught.exception.report['duplicates'], 1)

    def test_stale_queue_and_negative_window(self):
        for quiet in (0, 10):
            queue = DatagramQueue([(packet(), PEER)], timeout=0.5)
            with self.subTest(quiet=quiet), self.assertRaises(receiver.ReceiverError):
                receiver.check_empty(queue, quiet)
            self.assertEqual(queue.timeout, 0.5)
        queue = DatagramQueue(timeout=0.5)
        self.assertTrue(receiver.check_empty(queue, 10))
        self.assertEqual(queue.timeout, 0.5)
        self.assertIn(0, queue.timeouts)

    def test_missing_packet_and_partial_batch_timeout(self):
        for packets, accepted in (([], []), ([(packet(), PEER)], [7])):
            queue = DatagramQueue(packets, timeout=0.5)
            with self.subTest(accepted=accepted), self.assertRaises(receiver.ReceiverError) as caught:
                receiver.receive_expected(queue, COOKIE, 7, count=2)
            self.assertTrue(caught.exception.report['timed_out'])
            self.assertEqual(caught.exception.report['accepted'], accepted)
            self.assertFalse(caught.exception.report['passed'])
            self.assertEqual(queue.timeout, 0.5)

    def test_one_deadline_covers_whole_batch(self):
        queue = DatagramQueue([(packet(), PEER), (packet(8), PEER)])
        with mock.patch.object(receiver.time, 'monotonic', side_effect=[10, 10.1, 11.1]):
            with self.assertRaises(receiver.ReceiverError) as caught:
                receiver.receive_expected(queue, COOKIE, 7, count=2, timeout_ms=1000)
        self.assertEqual(caught.exception.report['accepted'], [7])
        self.assertTrue(caught.exception.report['timed_out'])
        self.assertEqual(len(queue.datagrams), 1)

    def test_interruptions_share_same_deadline(self):
        queue = DatagramQueue([InterruptedError(), (packet(), PEER)])
        with mock.patch.object(receiver.time, 'monotonic', side_effect=[10, 10.1, 10.2]):
            result = receiver.receive_expected(queue, COOKIE, 7, settle_ms=0)
        self.assertTrue(result['passed'])
        self.assertAlmostEqual(queue.timeouts[0], 0.9)
        self.assertAlmostEqual(queue.timeouts[1], 0.8)

    def test_socket_error_restores_timeout(self):
        for operation in (lambda queue: receiver.receive_expected(queue, COOKIE, 7), receiver.check_empty):
            queue = DatagramQueue([OSError(errno.EBADF, 'closed')], timeout=4)
            with self.subTest(operation=operation), self.assertRaises(OSError):
                operation(queue)
            self.assertEqual(queue.timeout, 4)

    def test_ranges_fail_before_socket_access(self):
        defaults = dict(cookie=COOKIE, first_sequence=7, count=1, timeout_ms=1000, settle_ms=100)
        invalid = dict(cookie=(-1, 0x100000000, True, 1.0),
                       first_sequence=(0, -1, 0x100000000, True, '7'),
                       count=(0, 1025, -1, True, 1.0),
                       timeout_ms=(0, 60001, -1, float('nan'), True),
                       settle_ms=(-1, 5001, float('inf'), True))
        for name, values in invalid.items():
            for value in values:
                queue = mock.Mock()
                with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                    receiver.receive_expected(queue, **dict(defaults, **{name: value}))
                self.assertEqual(queue.mock_calls, [])
        with self.assertRaisesRegex(ValueError, 'wrap'):
            receiver.receive_expected(None, COOKIE, 0xFFFFFFFF, count=2)


class LocalSocketTests(unittest.TestCase):
    def test_real_nonblocking_empty_queue_and_timeout(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            sock.settimeout(2)
            self.assertTrue(receiver.check_empty(sock))
            self.assertTrue(receiver.check_empty(sock, 2))
            with self.assertRaises(receiver.ReceiverError) as caught:
                receiver.receive_expected(sock, COOKIE, 7, timeout_ms=2)
            self.assertTrue(caught.exception.report['timed_out'])
            self.assertEqual(sock.gettimeout(), 2)

    def test_real_stale_queue_is_rejected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sock.bind(('127.0.0.1', 0))
                sender.sendto(packet(), sock.getsockname())
                with self.assertRaises(receiver.ReceiverError) as caught:
                    receiver.check_empty(sock, 1000)
                self.assertEqual(caught.exception.report['unexpected']['captured_bytes'], 86)

    def test_real_oversize_datagram_cannot_truncate_to_valid_length(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sock.bind(('127.0.0.1', 0))
                sender.sendto(packet() + bytes(2000), sock.getsockname())
                with self.assertRaises(receiver.ReceiverError) as caught:
                    receiver.receive_expected(sock, COOKIE, 7)
                self.assertIn('length mismatch', str(caught.exception))
                self.assertEqual(caught.exception.report['unexpected']['captured_bytes'], 87)

    def test_real_socket_checks_source(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sock.bind(('127.0.0.1', 0))
                sender.sendto(packet(), sock.getsockname())
                with self.assertRaisesRegex(receiver.ReceiverError, 'source mismatch'):
                    receiver.receive_expected(sock, COOKIE, 7)

    def test_bind_does_not_share_existing_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
            occupied.bind(('127.0.0.1', 0))
            with self.assertRaises(OSError):
                receiver.open_receiver('127.0.0.1', occupied.getsockname()[1])


class ApiTests(unittest.TestCase):
    def test_context_expect_and_silence(self):
        queue = DatagramQueue()
        with mock.patch.object(receiver, 'open_receiver', return_value=queue) as opened:
            with receiver.receiver('192.168.1.120', 49153) as peer:
                queue.datagrams.append((packet(), PEER))
                self.assertEqual(peer.expect(7, COOKIE, timeout=1)['accepted'], [7])
                self.assertTrue(peer.expect_silence(timeout=0.25)['passed'])
            opened.assert_called_once_with('192.168.1.120', 49153)
        self.assertTrue(queue.closed)

    def test_negative_leak_raises_and_closes(self):
        queue = DatagramQueue()
        with mock.patch.object(receiver, 'open_receiver', return_value=queue):
            with self.assertRaises(receiver.ReceiverError) as caught:
                with receiver.receiver('192.168.1.120') as peer:
                    queue.datagrams.append((packet(), PEER))
                    peer.expect_silence(0.25)
        self.assertFalse(caught.exception.report['passed'])
        self.assertEqual(caught.exception.report['unexpected']['marker_hex'], packet()[:20].hex())
        self.assertTrue(queue.closed)

    def test_constructor_stale_queue_closes(self):
        queue = DatagramQueue([(packet(), PEER)])
        with mock.patch.object(receiver, 'open_receiver', return_value=queue):
            with self.assertRaises(receiver.ReceiverError):
                receiver.receiver('192.168.1.120')
        self.assertTrue(queue.closed)

    def test_timeout_seconds_ranges(self):
        for invalid in (-1, True, '1', float('nan'), float('inf'), 61):
            with self.subTest(timeout=invalid), self.assertRaises(ValueError):
                receiver.timeout_milliseconds(invalid, 60)
        self.assertEqual(receiver.timeout_milliseconds(0.25, 5), 250)
        self.assertEqual(receiver.timeout_milliseconds(0.001, 60), 1)
        self.assertEqual(receiver.timeout_milliseconds(0, 5, allow_zero=True), 0)
        with self.assertRaises(ValueError):
            receiver.timeout_milliseconds(0, 60)


class CommandTests(unittest.TestCase):
    arguments = ['--bind-ip', '192.168.1.120', '--cookie', '0x10203040', '--seq', '7']

    def invoke(self, datagrams, arguments=None):
        queue = DatagramQueue(datagrams)
        output = io.StringIO()
        with mock.patch.object(receiver, 'open_receiver', return_value=queue) as opened:
            with contextlib.redirect_stdout(output):
                result = receiver.main(self.arguments if arguments is None else arguments)
        return result, [json.loads(line) for line in output.getvalue().splitlines()], queue, opened

    def test_ready_before_receive_then_success(self):
        result, output, queue, opened = self.invoke([BlockingIOError(), (packet(), PEER)])
        self.assertEqual(result, 0)
        self.assertEqual(len(output), 2)
        self.assertTrue(output[0]['ready'])
        self.assertEqual(output[0]['payload_bytes'], 86)
        self.assertEqual(output[0]['source'], '192.0.2.1:49152')
        self.assertTrue(output[1]['passed'])
        opened.assert_called_once_with('192.168.1.120', 49153)
        self.assertTrue(queue.closed)

    def test_stale_queue_has_no_ready_message(self):
        result, output, queue, opened = self.invoke([(packet(), PEER)])
        self.assertEqual(result, 1)
        self.assertEqual(len(output), 1)
        self.assertFalse(output[0]['passed'])
        self.assertNotIn('ready', output[0])
        self.assertTrue(queue.closed)

    def test_timeout_and_duplicate_exit_nonzero(self):
        for datagrams in ([BlockingIOError()], [BlockingIOError(), (packet(), PEER), (packet(), PEER)]):
            with self.subTest(datagrams=datagrams):
                result, output, queue, opened = self.invoke(datagrams)
                self.assertEqual(result, 1)
                self.assertTrue(output[0]['ready'])
                self.assertFalse(output[-1]['passed'])
                self.assertTrue(queue.closed)

    def test_invalid_cli_never_opens_socket(self):
        options = [('--seq', '0'), ('--cookie', '-1'), ('--cookie', '4294967296'),
                   ('--count', '0'), ('--count', '1025'), ('--timeout-ms', '0'),
                   ('--timeout-ms', '60001'), ('--settle-ms', '-1'), ('--settle-ms', '5001'),
                   ('--port', '0'), ('--port', '65536'), ('--bind-ip', '0.0.0.0'),
                   ('--bind-ip', '::1'), ('--bind-ip', '224.0.0.1'), ('--coo', '1')]
        for option in options:
            with self.subTest(option=option), mock.patch.object(receiver, 'open_receiver') as opened:
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                    receiver.main(self.arguments + list(option))
                self.assertEqual(caught.exception.code, 2)
                opened.assert_not_called()

    def test_uint32_parser_is_ascii_and_bounded(self):
        for text, value in (('0', 0), ('4294967295', 0xFFFFFFFF), ('0xffffffff', 0xFFFFFFFF), ('0X10', 16)):
            self.assertEqual(receiver.parse_uint32(text), value)
        for text in ('', '+1', '-1', '0x', '0xz', '4294967296', '１２', '١٢', '1.0', ' 1', '0x100000000'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                receiver.parse_uint32(text)

    def test_bind_failure_closes_socket(self):
        sock = mock.Mock()
        sock.bind.side_effect = OSError(errno.EADDRINUSE, 'occupied')
        with mock.patch.object(receiver.socket, 'socket', return_value=sock):
            with self.assertRaises(OSError):
                receiver.open_receiver('192.168.1.120')
        sock.close.assert_called_once()
        sock.setsockopt.assert_not_called()

    def test_cli_bind_error_is_json_failure(self):
        output = io.StringIO()
        with mock.patch.object(receiver, 'open_receiver', side_effect=OSError(errno.EADDRINUSE, 'occupied')):
            with contextlib.redirect_stdout(output):
                self.assertEqual(receiver.main(self.arguments), 1)
        self.assertFalse(json.loads(output.getvalue())['passed'])


if __name__ == '__main__':
    unittest.main()
