#!/usr/bin/env python3
"""Receive fixed IPv4 PON probe payloads after LAN1 DNAT, without raw sockets.

CLI: --bind-ip 192.168.1.120 --cookie 0x12345678 --seq 7 [--count 1]
Port defaults to 49153. Wait for the flushed JSON ready line before sending.
The final JSON reports success or failure; exit status is zero only on success.
Sequences are consecutive and ordered. Any unexpected or duplicate datagram
fails the run. The deadline covers the complete batch, followed by a bounded
quiet interval and an immediate empty-queue check. Marker cookies must come
from this module load's prior ER capture, not from the packet being checked.

Runner API: with receiver(host, 49153) as rx, inject one packet, then call
rx.expect(sequence, cookie, timeout=1.0). For a negative packet, use
rx.expect_silence(timeout=0.25). Timeouts are seconds; keep the socket open
across phases. Methods return result dictionaries and raise ReceiverError
with a .report dictionary on packet validation failures or receive timeouts.
Context exit or close() releases the socket. Packet validation checks the
exact source, 86-byte UDP payload length and all 20 marker bytes.
"""
import argparse
import ipaddress
import json
import math
import re
import socket
import struct
import time


MAGIC = 0x4354504E
FRAME_BYTES = 128
MARKER_BYTES = 20
PAYLOAD_BYTES = FRAME_BYTES - 14 - 20 - 8
SOURCE_IP = '192.0.2.1'
SOURCE_PORT = 49152
DESTINATION_PORT = 49153
IPV4_KIND = 0
UINT32_MAX = 0xFFFFFFFF
MAX_COUNT = 1024
MAX_DATAGRAM = PAYLOAD_BYTES + 1


class ReceiverError(RuntimeError):
    def __init__(self, message, report):
        super().__init__(message)
        self.report = dict(report, passed=False, error=message)


def bounded(value, minimum, maximum, name):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f'{name} must be an integer in {minimum}..{maximum}')
    return value


def parse_uint32(text):
    if re.fullmatch(r'0[xX][0-9a-fA-F]{1,8}', text):
        return int(text, 16)
    if not re.fullmatch(r'[0-9]{1,10}', text):
        raise ValueError('expected an unsigned decimal or hexadecimal 32-bit integer')
    return bounded(int(text, 10), 0, UINT32_MAX, 'integer')


def parse_ipv4(text):
    address = ipaddress.IPv4Address(text)
    if address.is_unspecified or address.is_multicast or address == ipaddress.IPv4Address('255.255.255.255'):
        raise ValueError('bind address must be a specific unicast IPv4 address')
    return str(address)


def expected_marker(sequence, cookie):
    bounded(sequence, 1, UINT32_MAX, 'sequence')
    bounded(cookie, 0, UINT32_MAX, 'cookie')
    return struct.pack('!5I', MAGIC, sequence, cookie, IPV4_KIND, FRAME_BYTES)


def validate_datagram(payload, peer, sequence, cookie):
    expected = expected_marker(sequence, cookie)
    if len(payload) != PAYLOAD_BYTES:
        raise ValueError(f'UDP payload length mismatch: {len(payload)}, expected {PAYLOAD_BYTES}')
    if peer != (SOURCE_IP, SOURCE_PORT):
        raise ValueError(f'UDP source mismatch: {peer!r}')
    if payload[:MARKER_BYTES] != expected:
        raise ValueError(f'marker mismatch: {payload[:MARKER_BYTES].hex()}, expected {expected.hex()}')
    return dict(sequence=sequence, cookie=cookie, kind='ipv4', frame_bytes=FRAME_BYTES,
                payload_bytes=PAYLOAD_BYTES, source=f'{SOURCE_IP}:{SOURCE_PORT}',
                payload_hex=payload.hex())


def describe_datagram(payload, peer):
    return dict(peer=peer, captured_bytes=len(payload), marker_hex=payload[:MARKER_BYTES].hex())


def read_until(sock, deadline):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout('receive deadline expired')
        sock.settimeout(remaining)
        try:
            return sock.recvfrom(MAX_DATAGRAM)
        except InterruptedError:
            continue


def check_empty(sock, quiet_ms=0):
    """Require silence for quiet_ms, then an empty queue; never discard stale data."""
    bounded(quiet_ms, 0, 5000, 'quiet_ms')
    previous_timeout = sock.gettimeout()
    try:
        if quiet_ms:
            try:
                payload, peer = read_until(sock, time.monotonic() + quiet_ms / 1000)
            except socket.timeout:
                pass
            else:
                raise ReceiverError('unexpected datagram during quiet interval',
                                    dict(queue_empty=False, unexpected=describe_datagram(payload, peer)))
        sock.settimeout(0)
        try:
            payload, peer = sock.recvfrom(MAX_DATAGRAM)
        except BlockingIOError:
            return True
        raise ReceiverError('receive queue is not empty',
                            dict(queue_empty=False, unexpected=describe_datagram(payload, peer)))
    finally:
        sock.settimeout(previous_timeout)


def validate_options(cookie, first_sequence, count, timeout_ms, settle_ms):
    expected_marker(first_sequence, cookie)
    bounded(count, 1, MAX_COUNT, 'count')
    if first_sequence + count - 1 > UINT32_MAX:
        raise ValueError('sequence range would wrap')
    bounded(timeout_ms, 1, 60000, 'timeout_ms')
    bounded(settle_ms, 0, 5000, 'settle_ms')


def is_duplicate(unexpected, accepted, cookie):
    if unexpected['captured_bytes'] != PAYLOAD_BYTES or unexpected['peer'] != (SOURCE_IP, SOURCE_PORT):
        return False
    marker = bytes.fromhex(unexpected['marker_hex'])
    if len(marker) != MARKER_BYTES:
        return False
    sequence = struct.unpack('!5I', marker)[1]
    return sequence in accepted and marker == expected_marker(sequence, cookie)


def receive_expected(sock, cookie, first_sequence, count=1, timeout_ms=1000, settle_ms=100):
    """Call after arming the receiver and injecting a bounded batch of packets."""
    validate_options(cookie, first_sequence, count, timeout_ms, settle_ms)
    report = dict(passed=False, timed_out=False, accepted=[], observations=[], rejected=0,
                  duplicates=0, queue_empty=False, cookie=cookie, first_sequence=first_sequence,
                  count=count, source=f'{SOURCE_IP}:{SOURCE_PORT}', payload_bytes=PAYLOAD_BYTES,
                  timeout_ms=timeout_ms, settle_ms=settle_ms)
    previous_timeout = sock.gettimeout()
    deadline = time.monotonic() + timeout_ms / 1000
    try:
        while len(report['accepted']) < count:
            try:
                payload, peer = read_until(sock, deadline)
            except socket.timeout as error:
                report['timed_out'] = True
                raise ReceiverError('timed out waiting for the expected UDP marker', report) from error
            sequence = first_sequence + len(report['accepted'])
            try:
                observation = validate_datagram(payload, peer, sequence, cookie)
            except ValueError as error:
                report['unexpected'] = describe_datagram(payload, peer)
                report['rejected'] = 1
                report['duplicates'] = int(is_duplicate(report['unexpected'], report['accepted'], cookie))
                raise ReceiverError(str(error), report) from error
            report['accepted'].append(sequence)
            report['observations'].append(observation)
        try:
            check_empty(sock, settle_ms)
        except ReceiverError as error:
            report.update(error.report)
            report['rejected'] = 1
            report['duplicates'] = int(is_duplicate(report['unexpected'], report['accepted'], cookie))
            raise ReceiverError(str(error), report) from error
        report.update(passed=True, queue_empty=True)
        return report
    finally:
        sock.settimeout(previous_timeout)


def open_receiver(bind_ip, port=DESTINATION_PORT):
    address = parse_ipv4(bind_ip)
    bounded(port, 1024, 65535, 'port')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((address, port))
    except BaseException:
        sock.close()
        raise
    return sock


def timeout_milliseconds(timeout, maximum, allow_zero=False):
    if type(timeout) not in (int, float) or not math.isfinite(timeout):
        raise ValueError('timeout must be a finite number of seconds')
    minimum = 0 if allow_zero else 0.001
    if not minimum <= timeout <= maximum:
        raise ValueError(f'timeout must be in {minimum}..{maximum} seconds')
    return math.ceil(timeout * 1000)


class receiver:
    def __init__(self, bind_ip, port=DESTINATION_PORT):
        self.sock = open_receiver(bind_ip, port)
        try:
            check_empty(self.sock)
        except BaseException:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.close()

    def close(self):
        self.sock.close()

    def expect(self, sequence, cookie, timeout=1.0):
        return receive_expected(self.sock, cookie, sequence,
                                timeout_ms=timeout_milliseconds(timeout, 60))

    def expect_silence(self, timeout=0.25):
        quiet_ms = timeout_milliseconds(timeout, 5, allow_zero=True)
        check_empty(self.sock, quiet_ms)
        return dict(passed=True, queue_empty=True, quiet_ms=quiet_ms)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--bind-ip', type=parse_ipv4, required=True)
    parser.add_argument('--port', type=int, default=DESTINATION_PORT)
    parser.add_argument('--cookie', type=parse_uint32, required=True)
    parser.add_argument('--seq', type=parse_uint32, required=True)
    parser.add_argument('--count', type=int, default=1)
    parser.add_argument('--timeout-ms', type=int, default=1000)
    parser.add_argument('--settle-ms', type=int, default=100)
    args = parser.parse_args(argv)
    try:
        validate_options(args.cookie, args.seq, args.count, args.timeout_ms, args.settle_ms)
        bounded(args.port, 1024, 65535, 'port')
    except ValueError as error:
        parser.error(str(error))
    try:
        with open_receiver(args.bind_ip, args.port) as sock:
            check_empty(sock)
            print(json.dumps(dict(ready=True, bind_ip=args.bind_ip, port=args.port,
                                  source=f'{SOURCE_IP}:{SOURCE_PORT}', cookie=args.cookie,
                                  first_sequence=args.seq, count=args.count, payload_bytes=PAYLOAD_BYTES),
                             sort_keys=True), flush=True)
            report = receive_expected(sock, args.cookie, args.seq, args.count,
                                      args.timeout_ms, args.settle_ms)
    except ReceiverError as error:
        print(json.dumps(error.report, sort_keys=True), flush=True)
        return 1
    except OSError as error:
        print(json.dumps(dict(passed=False, error=str(error)), sort_keys=True), flush=True)
        return 1
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
