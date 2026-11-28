#!/usr/bin/env python3
"""Exercise an already prepared, isolated production GPON RAM session."""
import argparse
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import subprocess
import time
import uuid

from prepare_npu_ram import require
from run_npu_loopback import fields


FLOW = '/sys/kernel/debug/ppe/pon_npu_flow'
PROBE = '/sys/kernel/debug/ct_pon_loopback/'


def session_fields(text):
    lines = text.splitlines()
    require(bool(lines), 'empty session status')
    current = fields(lines[0])
    require({'cookie', 'serial', 'phase', 'bound', 'hash', 'error'} <= current.keys(),
            'incomplete session status header')
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=40)
    parser.add_argument('--conntrack', default='/usr/sbin/conntrack')
    parser.add_argument('--withdraw', choices=('conntrack', 'table'), default='conntrack')
    args = parser.parse_args()
    uuid.UUID(args.boot)
    require(35 <= args.seconds <= 90, 'duration must cross the 30-second flow timeout')
    require(not args.output.resolve().is_relative_to(Path(__file__).resolve().parents[5]),
            'evidence must be outside ponwrt')
    args.output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-i', str(args.key), '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(args.pin),
           '-o', 'ProxyCommand=/usr/bin/nc -4 -b en6 -G 4 %h %p', 'root@192.168.1.1']
    guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(args.boot) +
             '; test "$(wc -l </proc/mtd)" = 1; ')
    report = dict(boot=args.boot, passed=False, released=False, start_attempted=False,
                  withdraw=args.withdraw, seconds=args.seconds, observations=[], packets=[], timestamps=[])
    ordinal = 0

    def remote(label, command):
        nonlocal ordinal
        ordinal += 1
        evidence = args.output / f'{ordinal:03}-{label}.json'
        try:
            result = subprocess.run(ssh + [guard + command], capture_output=True, text=True, timeout=20)
        except Exception as error:
            evidence.write_text(json.dumps(dict(command=command, error=repr(error)), indent=2) + '\n')
            raise
        evidence.write_text(json.dumps(dict(
            command=command, returncode=result.returncode, stdout=result.stdout, stderr=result.stderr), indent=2) + '\n')
        result.check_returncode()
        return result.stdout

    def write(path, command):
        return remote('write', 'echo ' + shlex.quote(command) + ' > ' + path)

    def state():
        return remote('state', 'cat ' + FLOW)

    def snapshot():
        return fields(remote('probe', 'cat ' + PROBE + 'status'))

    sock = None
    failure = None
    cookie = None

    def send(reply=False):
        nonlocal cookie
        before = snapshot()
        write(PROBE + 'command', 'send-fixed ipv4 0 tx')
        payload, peer = sock.recvfrom(2048)
        require(peer == ('192.168.1.1', 49152) and len(payload) == 86, 'LAN tuple or length mismatch')
        magic, sequence, received_cookie, kind, length = struct.unpack('!5I', payload[:20])
        require((magic, kind, length) == (0x4354504e, 0, 128) and
                sequence == int(before['sequence']) + 1, 'LAN marker mismatch')
        if cookie is None:
            cookie = received_cookie
        require(cookie == received_cookie, 'probe identity changed')
        report['packets'].append(dict(sequence=sequence, cookie=cookie, peer=peer, bytes=len(payload)))
        if reply:
            sock.sendto(b'PON_SESSION_REPLY', peer)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('192.168.1.120', 49153))
        sock.settimeout(3)
        initial = snapshot()
        report['initial_probe'] = initial
        require(initial['production_session'] == '1' and initial['configured'] == '1' and
                initial['mapped_service'] == '8500' and initial['npu_owner'] == '0', 'probe is not prepared')
        report['initial_session'] = session_fields(state())
        require(report['initial_session']['cookie'] == '0', 'session already owned')
        remote('table', 'nft list table ip pon_session')
        for attempt in range(8):
            send(reply=attempt == 0)
            time.sleep(.2)
            current = state()
            candidates = re.findall(r'^candidate cookie=(\d+) serial=(\d+) service=8500$', current, re.M)
            if candidates:
                break
        require(len(candidates) == 1, 'expected one observed candidate')
        selected_cookie, serial = candidates[0]
        report['candidate'] = dict(cookie=selected_cookie, serial=serial)
        report['start_attempted'] = True
        write(FLOW, 'start ' + selected_cookie + ' ' + serial)
        for attempt in range(60):
            send()
            current = session_fields(state())
            require(current['error'] == '0', 'session failed during learning')
            if current['bound'] == '1':
                break
            time.sleep(.05)
        require(current['bound'] == '1' and current['phase'] == '15', 'hardware binding timed out')
        baseline = snapshot()
        hardware_hash = int(current['hash'])
        report['hardware_hash'] = hardware_hash
        timestamps = report['timestamps']
        bound_started = time.monotonic()
        for sample in range(args.seconds):
            send()
            current = session_fields(state())
            after = snapshot()
            require(current['cookie'] == selected_cookie and current['serial'] == serial and
                    current['bound'] == '1' and current['phase'] == '15' and current['error'] == '0' and
                    int(current['hash']) == hardware_hash,
                    'active session retired')
            require(after['rx_data'] == baseline['rx_data'] and
                    after['rx_delivered'] == baseline['rx_delivered'], 'bound traffic reached CPU')
            rows = remote('row', 'cat /sys/kernel/debug/ppe/entries')
            row = next((line for line in rows.splitlines()
                        if re.match(r'^0*' + format(hardware_hash, 'x') + r' BND ', line)), None)
            require(row is not None, 'bound row disappeared')
            values = fields(row)
            require(values['orig'] == '192.0.2.1:49152->192.0.2.2:49153' and
                    values['new'] == '192.168.1.1:49152->192.168.1.120:49153', 'NAT action changed')
            ib1 = int(values['ib1'], 16)
            require(not ib1 & (1 << 31), 'bound row is static')
            timestamps.append(ib1 & 0x7fff)
            report['observations'].append(dict(sample=sample, elapsed=time.monotonic() - bound_started,
                                               session=current, probe=after, row=row))
            time.sleep(1)
        report['bound_seconds'] = time.monotonic() - bound_started
        require(len(set(timestamps)) > 1, 'hardware activity timestamp did not advance')
        if args.withdraw == 'conntrack':
            remote('withdraw', 'nft flush chain ip pon_session forward; ' +
                   shlex.quote(args.conntrack) +
                   ' -D -p udp --orig-src 192.0.2.1 --orig-dst 192.0.2.2' +
                   ' --sport 49152 --dport 49153')
        else:
            remote('withdraw', 'nft delete table ip pon_session')
        for attempt in range(10):
            current_text = state()
            if 'candidate ' not in current_text and session_fields(current_text)['bound'] == '0':
                break
            time.sleep(1)
        require('candidate ' not in current_text and session_fields(current_text)['bound'] == '0',
                args.withdraw + ' withdrawal did not retire candidate')
        rows = remote('rows-after', 'cat /sys/kernel/debug/ppe/entries')
        require(not any(re.match(r'^0*' + format(hardware_hash, 'x') + r' BND ', line)
                        for line in rows.splitlines()), 'withdrawn row remains bound')
        before = snapshot()
        send()
        after = snapshot()
        require(int(after['rx_data']) == int(before['rx_data']) + 1 and
                int(after['rx_delivered']) == int(before['rx_delivered']) + 1,
                'withdrawal did not restore CPU forwarding')
        report.update(passed=True, hardware_hash=hardware_hash, timestamps=timestamps,
                      withdrawal=dict(before=before, after=after, state=current_text))
    except Exception as error:
        failure = error
        report['error'] = repr(error)
    finally:
        try:
            if report['start_attempted']:
                write(FLOW, 'release')
                report['final_session'] = session_fields(state())
                report['released'] = report['final_session']['cookie'] == '0'
                require(report['released'], 'owner release incomplete')
        except Exception as error:
            report['cleanup_error'] = repr(error)
            failure = failure or error
        try:
            if sock is not None:
                sock.close()
        except Exception as error:
            report['socket_error'] = repr(error)
            failure = failure or error
        report['passed'] = report['passed'] and report['released'] and failure is None
        try:
            (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        except Exception as error:
            report['report_error'] = repr(error)
            report['passed'] = False
            failure = failure or error
        print(json.dumps({name: report.get(name) for name in
                          ('passed', 'released', 'error', 'cleanup_error', 'socket_error', 'report_error')}), flush=True)
    if failure is not None:
        raise failure


if __name__ == '__main__':
    main()
