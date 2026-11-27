#!/usr/bin/env python3
import argparse
import json
import ipaddress
from pathlib import Path
import re
import shlex
import struct
import subprocess
import time
import uuid

from prepare_npu_ram import require, sha256


DIAG = '/sys/kernel/debug/ppe/pon_npu_diag'
PROBE = '/sys/kernel/debug/ct_pon_loopback/'
CLASSIFIER = '/sys/bus/platform/devices/1fb50000.ethernet/ct_pon_cpu_probe'
POLICY = '/sys/bus/platform/devices/1fb50000.ethernet/ct_native_pair_policy'


def fields(text):
    return dict(re.findall(r'\b([a-z][a-z0-9_]*)=([^\s]+)', text))


def check_session(state, auth_count=0, learn=False):
    for name, expected in dict(owner=1, diagnostic=1, qualified=0, policy=0, fallback=0,
                                route_owner=1, fe_owner=1, ingress=1, phase=15,
                                error=0, invalidated=0, ring=1, auth_count=auth_count, auth_enabled=1,
                                auth_inflight=0, gate_mask=4, gate_closed=0, gate_fault=0,
                                gate_error=0, auth_error=0, er_error=0, er_fault=0,
                                dropped=0, fault=0).items():
        require(int(state[name]) == expected, 'diagnostic state: ' + name)
    require(int(state['flow'], 16) == 0 and (int(state['tb'], 16) >> 4 & 3) == 2 and
            int(state['scope'], 16) == 0x01000004 and
            int(state['ports'], 16) == 0x01000004 and int(state['gdm2'], 16) & 0xffff == 0x8888,
            'bank1 learning or ingress scope changed')
    if learn:
        require(state['learn_mode'] == '1' and state['next_row'] == '8192' and
                int(state['bank0_flow'], 16) == 0x2000 and
                (int(state['bank0_tb'], 16) >> 4 & 3) == 3 and
                state['bank0_next_row'] == '0', 'PPE learning configuration mismatch')
    require(all(state[family + '_' + name] == state[name]
                for family in ('gate', 'auth') for name in ('epoch', 'generation')),
            'GATE/AUTH transaction identity mismatch')


def check_packet(diag, probe, service, count, kind, previous, auth_count=0, learn=False):
    state, packet = fields(diag), fields(probe)
    check_session(state, auth_count, learn)
    for name in ('packets', 'consumed'):
        require(int(state[name]) == count, 'diagnostic state: ' + name)
    require(int(packet['sequence']) == previous + 1 and
            packet['sequence'] == packet['rx_sequence'] and packet['error'] == '0' and
            packet['tx_kind'] == packet['rx_kind'] == kind and packet['pending'] == '0',
            'numbered RX did not match TX')
    descriptor = [int(word, 16) for word in state['er_desc'].split('/')]
    require(len(descriptor) == 16 and descriptor[0] == 0x80000080 and
            descriptor[1] == int(state['epoch']) and descriptor[2] == count and
            descriptor[3] == 2 and descriptor[4] == int(state['generation']) and
            descriptor[5] == 0x80000000 | service and not descriptor[7], 'ER identity mismatch')
    require(descriptor[8] & 0xffff == 128 and descriptor[10] == 7 and
            descriptor[13] >> 28 == 6 and descriptor[14] & 31 == 2 and
            descriptor[9] & 0xffff == service, 'FE prefix mismatch')
    frame = bytes.fromhex(state['er_frame'])
    offset = 14 + (40 if kind == 'ipv6' else 20) + 8
    require(len(frame) == 128 and int(state['frame_bytes']) == 128, 'ER frame length')
    magic, sequence, cookie, packet_kind, length = struct.unpack_from('>5I', frame, offset)
    require(magic == 0x4354504e and sequence == previous + 1 and
            packet_kind == (1 if kind == 'ipv6' else 0) and length == 128, 'ER packet marker')
    require(int(state['observed_produced']) == count and int(state['observed_consumed']) == count,
            'ER producer/consumer evidence mismatch')
    return dict(service=service, kind=kind, sequence=sequence, cookie=cookie,
                er_sequence=count, epoch=descriptor[1], generation=descriptor[4], descriptor=descriptor)


def main():
    parser = argparse.ArgumentParser(description='Run bounded PON NPU ER diagnostics in a pinned RAM boot')
    parser.add_argument('--pin', type=Path, required=True)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--firmware-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--capture-service', type=lambda value: int(value, 0),
                        help='Capture raw ER metadata for one 16-bit service without accepting it as a matrix pass')
    modes.add_argument('--auth', action='store_true', help='Verify one exact AUTH rule against bounded match/miss packets')
    modes.add_argument('--learn', action='store_true', help='Verify exact AUTH with bounded PPE unbound row learning')
    parser.add_argument('--bind-host-ip', help='After learning, bind the exact tuple to this LAN1 IPv4 receiver')
    parser.add_argument('--bind-host-mac', help='LAN1 receiver MAC, required with --bind-host-ip')
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if args.bind_host_ip or args.bind_host_mac:
        require(args.learn and args.bind_host_ip and args.bind_host_mac,
                'LAN1 binding requires --learn and both receiver addresses')
        args.bind_host_ip = str(ipaddress.IPv4Address(args.bind_host_ip))
        require(re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', args.bind_host_mac),
                'invalid LAN1 receiver MAC')
    args.auth = args.auth or args.learn
    if args.capture_service is not None:
        require(0 <= args.capture_service <= 65535, 'capture service out of range')
    uuid.UUID(args.boot)
    blob = args.module.read_bytes()
    require(sha256(blob) == args.sha256, 'module hash mismatch')
    require(re.fullmatch('[0-9a-f]{64}', args.firmware_sha256), 'invalid firmware hash')
    args.output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=yes',
           '-o', 'UserKnownHostsFile=' + str(args.pin.resolve()),
           '-o', 'ProxyCommand=/usr/bin/nc -4 -b en6 -G 4 %h %p']
    if args.identity:
        ssh += ['-i', str(args.identity.resolve())]
    ssh += ['root@192.168.1.1']
    guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(args.boot) +
             '; test "$(wc -l </proc/mtd)" = 1; ')

    def remote(label, command, data=None):
        result = subprocess.run(ssh + [guard + command], input=data, capture_output=True, timeout=30)
        (args.output / (label + '.stdout')).write_bytes(result.stdout)
        (args.output / (label + '.stderr')).write_bytes(result.stderr)
        (args.output / (label + '.json')).write_text(json.dumps(dict(returncode=result.returncode)) + '\n')
        result.check_returncode()
        return result.stdout.decode()

    def write(label, path, command):
        return remote(label, 'echo ' + shlex.quote(command) + ' > ' + path)

    before = remote('before', 'cat ' + DIAG + '; cat ' + CLASSIFIER + '; cat ' + POLICY +
                    '; cat /sys/kernel/debug/gpio; ip -d link show pon0; ' +
                    'sha256sum /lib/firmware/airoha/hg5585f-ct/npu_rebuilt_rv32.bin')
    initial = fields(before)
    for name, expected in dict(owner=0, qualified=0, policy=0, fallback=0, route_owner=0, fe_owner=0,
                                gate_error=0, auth_error=0, er_error=0, gate_caps=15,
                                auth_caps=7, er_caps=15).items():
        require(int(initial[name]) == expected, 'preflight: ' + name)
    require(re.search(r'ram-pon-tx-disable[^\n]*out hi', before) and 'state DOWN' in before,
            'optical guard or interface state')
    require('tuple=0 pool=00000000 pool_pending=0 leases=0' in before and
            'saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0' in before and
            re.search(r'^generation=\d+ allowed=0 failed=0$', before, re.M), 'classifier or native policy busy')
    require(args.firmware_sha256 in before, 'board firmware mismatch')
    if not args.run:
        print(json.dumps(dict(preflight=True, output=str(args.output))))
        return
    report = dict(boot=args.boot, module_sha256=args.sha256, firmware_sha256=args.firmware_sha256,
                  pon_ppe_qualified=False, observations=[], cpu_observations=[],
                  matrix_passed=False, passed=False, restored=False)
    if args.auth:
        report.update(auth_mode=True, auth_observations=[])
    if args.learn:
        report.update(learn_mode=True, learned_rows=[])
    if args.bind_host_ip:
        report.update(bound_receiver=dict(ip=args.bind_host_ip, mac=args.bind_host_mac),
                      bound_observations=[])
    if args.capture_service is not None:
        report.update(capture_service=args.capture_service, captures=[])
    loaded = False
    baseline = ''
    failure = None
    ipv6 = remote('ipv6-before', 'cat /proc/sys/net/ipv6/conf/pon0/disable_ipv6').strip()
    require(ipv6 in ('0', '1'), 'invalid IPv6 state')
    try:
        write('ipv6-disable', '/proc/sys/net/ipv6/conf/pon0/disable_ipv6', '1')
        remote('upload', 'test ! -d /sys/module/ct_pon_loopback; cat > /tmp/ct_pon_loopback.ko', blob)
        remote('load', 'test "$(sha256sum /tmp/ct_pon_loopback.ko | cut -d " " -f1)" = ' +
               shlex.quote(args.sha256) + '; insmod /tmp/ct_pon_loopback.ko special_tag=1')
        loaded = True
        baseline = remote('baseline', 'cat ' + PROBE + 'status')
        write('prepare', PROBE + 'command', 'prepare')
        cookie = None
        for service in ((args.capture_service,) if args.capture_service is not None else (0, 0x8000)):
            prefix = 'service-' + str(service)
            alt_service = service ^ 1
            if args.bind_host_ip:
                write(prefix + '-map', PROBE + 'command', f'map-pair {service} {alt_service}')
            else:
                write(prefix + '-map', PROBE + 'command', 'map ' + str(service))
            start = ('start-learn ' if args.learn else 'start-auth ') + str(service) if args.auth else 'start'
            write(prefix + '-start', DIAG, start)
            remote(prefix + '-started', 'cat ' + DIAG)
            if args.capture_service is not None:
                for count, kind in enumerate(('ipv4', 'ipv6'), 1):
                    label = prefix + '-capture-' + kind
                    send_error = None
                    try:
                        write(label + '-send', PROBE + 'command', 'send-current ' + kind)
                    except subprocess.CalledProcessError as error:
                        require(error.returncode == 1 and error.stderr.strip() ==
                                b'ash: write error: Operation timed out', 'unexpected capture send failure')
                        send_error = 'RX marker timed out'
                    state = fields(remote(label + '-observation', 'cat ' + DIAG))
                    probe = fields(remote(label + '-probe', 'cat ' + PROBE + 'status'))
                    for name, expected in dict(owner=1, diagnostic=1, qualified=0, policy=0,
                                                fallback=0, invalidated=0, fault=0, ring=1,
                                                consumed=count, observed_consumed=count).items():
                        require(int(state[name]) == expected, 'capture state: ' + name)
                    descriptor = [int(word, 16) for word in state['er_desc'].split('/')]
                    frame = bytes.fromhex(state['er_frame'])
                    require(len(descriptor) == 16 and len(frame) == 128, 'capture shape')
                    marker = struct.unpack_from('>5I', frame, 14 + (40 if kind == 'ipv6' else 20) + 8)
                    require(marker[0] == 0x4354504e and marker[1] == int(probe['sequence']) and
                            marker[3] == (kind == 'ipv6') and marker[4] == 128, 'capture packet marker')
                    report['captures'].append(dict(service=service, kind=kind, descriptor=descriptor,
                        frame=frame.hex(), host_packets=int(state['packets']),
                        host_dropped=int(state['dropped']), send_error=send_error))
                continue
            if args.auth:
                returned = 0
                samples = [('ipv4', variant) for variant in range(5)] + [('ipv6', 0), ('ipv4', None), ('ipv4', 0)]
                for index, (kind, variant) in enumerate(samples * 2):
                    label = prefix + '-auth-' + str(index + 1)
                    previous = fields(remote(label + '-before', 'cat ' + PROBE + 'status'))
                    command = 'send-current ' + kind if variant is None else 'send-fixed ' + kind + ' ' + str(variant) + ' rx'
                    write(label + '-send', PROBE + 'command', command)
                    observed = remote(label + '-observation', 'cat ' + DIAG)
                    received = remote(label + '-received', 'cat ' + PROBE + 'status')
                    state, packet = fields(observed), fields(received)
                    matched = kind == 'ipv4' and variant == 0
                    require(packet['tx_fixed'] == str(int(variant is not None)) and
                            packet['tx_variant'] == str(variant or 0), 'AUTH packet shape mismatch')
                    if matched:
                        check_session(state, 1, args.learn)
                        require(state['auth_mode'] == '1' and
                                int(state['consumed']) == int(state['packets']) == returned,
                                'AUTH match unexpectedly returned through ER')
                        require(int(packet['sequence']) == int(previous['sequence']) + 1 and
                                packet['rx_sequence'] == packet['sequence'] and packet['error'] == '0' and
                                packet['pending'] == '0' and packet['tx_kind'] == packet['rx_kind'] == kind and
                                int(packet['received']) == int(previous['received']) + 1,
                                'AUTH matched RX marker missing')
                        require(int(packet['rx_data']) == int(previous['rx_data']) + 1 and
                                int(packet['rx_delivered']) == int(previous['rx_delivered']) + 1,
                                'AUTH match missing QDMA receive')
                        require(int(packet['rx_msg0'], 16) >> 14 & 0xffff == service,
                                'AUTH QDMA service mismatch')
                    else:
                        returned += 1
                        observation = check_packet(observed, received, service, returned, kind,
                                                   int(previous['sequence']), 1, args.learn)
                        if cookie is not None:
                            require(cookie == observation['cookie'], 'probe cookie changed')
                        cookie = observation['cookie']
                        report['observations'].append(observation)
                        require(packet['rx_data'] == previous['rx_data'] and
                                packet['rx_delivered'] == previous['rx_delivered'],
                                'AUTH mismatch unexpectedly received through QDMA')
                    report['auth_observations'].append(dict(service=service, kind=kind, variant=variant,
                        matched=matched, sequence=int(packet['rx_sequence']), er_consumed=returned,
                        rx_msg0=packet['rx_msg0'], rx_msg1=packet['rx_msg1'], rx_data=int(packet['rx_data'])))
            for index in range(0 if args.auth else 18):
                label = prefix + '-packet-' + str(index + 1)
                kind = 'ipv4' if index % 2 == 0 else 'ipv6'
                previous = int(fields(remote(label + '-before', 'cat ' + PROBE + 'status'))['sequence'])
                write(label + '-send', PROBE + 'command', 'send-current ' + kind)
                for attempt in range(10):
                    observed = remote(label + '-observation-' + str(attempt), 'cat ' + DIAG)
                    if int(fields(observed)['consumed']) == index + 1:
                        break
                    time.sleep(0.01)
                received = remote(label + '-received', 'cat ' + PROBE + 'status')
                observation = check_packet(observed, received, service, index + 1, kind, previous)
                if cookie is not None:
                    require(cookie == observation['cookie'], 'probe cookie changed')
                cookie = observation['cookie']
                report['observations'].append(observation)
            if args.learn:
                entries = remote(prefix + '-learned', 'cat /sys/kernel/debug/ppe/entries')
                rows = []
                expected = {'192.0.2.1:49152->192.0.2.2:49153'}
                for line in entries.splitlines():
                    match = re.match(r'^([0-9a-f]+)\s+(UNB|BND|FIN)\s+', line)
                    if not match:
                        continue
                    row_hash = int(match[1], 16)
                    require(not (0x2000 <= row_hash < 0x4000), 'unexpected bank1 entry during PON learning')
                    if 0 <= row_hash < 0x2000:
                        original = fields(line).get('orig')
                        require(match[2] == 'UNB' and original in expected,
                                'unexpected bank0 learned entry')
                        rows.append(dict(hash=row_hash, tuple=original, entry=line))
                require(len(rows) == 1 and {row['tuple'] for row in rows} == expected,
                        'expected the single authorized IPv4 tuple in bank0')
                target = next(row for row in rows if row['tuple'] == '192.0.2.1:49152->192.0.2.2:49153')
                matches = [entry for entry in report['auth_observations'] if entry['service'] == service and entry['matched']]
                require(all(int(entry['rx_msg1'], 16) & 0xffff == target['hash'] for entry in matches),
                        'QDMA learned hash differs from bank0 tuple')
                report['learned_rows'].append(dict(service=service, hash=target['hash'], entries=rows))
            if args.bind_host_ip:
                from run_npu_bound import run_bound_matrix
                baseline_rows = [row for row in rows if row['tuple'] ==
                                 '192.0.2.1:49152->192.0.2.2:49153']
                require(len(baseline_rows) == 1 and cookie is not None,
                        'missing learned row or independent ER cookie')
                run_bound_matrix(remote, write, DIAG, PROBE, fields, check_session, check_packet,
                                 service, baseline_rows[0]['hash'], args.bind_host_ip,
                                 args.bind_host_mac, cookie, report)
            write(prefix + '-close', DIAG, 'close')
            closed = fields(remote(prefix + '-closed', 'cat ' + DIAG))
            require(closed['ring'] == '0' and closed['gate_mask'] == '0' and closed['auth_enabled'] == '0'
                    and closed['qualified'] == '0' and closed['ingress'] == '0', 'close incomplete')
            if args.learn:
                require(closed['next_row'] == '8192' and closed['bank0_next_row'] == '8192',
                        'learned bank cleanup incomplete')
                entries = remote(prefix + '-cleared', 'cat /sys/kernel/debug/ppe/entries')
                require(not any(0 <= int(match[1], 16) < 0x4000 for match in
                                re.finditer(r'^([0-9a-f]+)\s+(?:UNB|BND|FIN)\s+', entries, re.M)),
                        'learned rows retained after close')
            for kind in ('ipv4', 'ipv6'):
                previous = fields(remote(prefix + '-cpu-' + kind + '-before', 'cat ' + PROBE + 'status'))
                write(prefix + '-cpu-' + kind, PROBE + 'command', 'send-current ' + kind)
                received = fields(remote(prefix + '-cpu-' + kind + '-after', 'cat ' + PROBE + 'status'))
                require(int(received['rx_sequence']) == int(previous['sequence']) + 1 and
                        int(received['received']) == int(previous['received']) + 1 and
                        received['tx_kind'] == received['rx_kind'] == kind and
                        received['error'] == '0' and received['pending'] == '0', 'CPU return after close missing')
                quiet = fields(remote(prefix + '-cpu-' + kind + '-quiet', 'cat ' + DIAG))
                require(quiet['ring'] == '0' and quiet['gate_mask'] == '0' and quiet['auth_enabled'] == '0'
                        and quiet['qualified'] == '0' and quiet['ingress'] == '0'
                        and quiet['consumed'] == closed['consumed'], 'closed path resumed')
                report['cpu_observations'].append(dict(service=service, kind=kind,
                    sequence=int(received['rx_sequence']), rx_msg0=received['rx_msg0'],
                    rx_msg1=received['rx_msg1'], er_consumed=int(quiet['consumed'])))
            write(prefix + '-release', DIAG, 'release')
            released = fields(remote(prefix + '-released', 'cat ' + DIAG))
            require(released['owner'] == released['route_owner'] == released['fe_owner'] == '0', 'owner release incomplete')
            require(released['flow'] == initial['flow'] and released['tb'] == initial['tb'], 'bank1 restore mismatch')
            require(released['bank0_flow'] == initial['bank0_flow'] and
                    released['bank0_tb'] == initial['bank0_tb'], 'bank0 restore mismatch')
        report['matrix_passed'] = args.capture_service is None
        if args.capture_service is not None:
            report['capture_completed'] = True
    except Exception as error:
        failure = error
        report['error'] = repr(error)
    finally:
        try:
            if loaded:
                try:
                    remote('cleanup-observation', 'cat ' + DIAG + '; cat ' + PROBE + 'status; dmesg | tail -60')
                except Exception as error:
                    report['snapshot_error'] = repr(error)
                write('cleanup-release', DIAG, 'release')
                released = fields(remote('cleanup-released', 'cat ' + DIAG))
                require(released['owner'] == released['route_owner'] == released['fe_owner'] == '0', 'cleanup owner retained')
                require(released['flow'] == initial['flow'] and released['tb'] == initial['tb'], 'cleanup bank1 mismatch')
                require(released['bank0_flow'] == initial['bank0_flow'] and
                        released['bank0_tb'] == initial['bank0_tb'], 'cleanup bank0 mismatch')
                write('restore', PROBE + 'command', 'restore')
                restored = remote('restored', 'cat ' + PROBE + 'status')
                require(restored.startswith('retained=0 controller=0 opened=0 saved=0 error=0 pending=0 '),
                        'module cleanup incomplete')
                original = re.findall(r'^([0-9a-f]{4})=([0-9a-f]{8}) ', baseline, re.M)
                actual = re.findall(r'^([0-9a-f]{4})=([0-9a-f]{8}) ', restored, re.M)
                require(len(original) == 10 and original == actual, 'loopback register restore mismatch')
                remote('unload', 'rmmod ct_pon_loopback')
            write('ipv6-restore', '/proc/sys/net/ipv6/conf/pon0/disable_ipv6', ipv6)
            remote('after', 'cat ' + DIAG + '; cat ' + CLASSIFIER + '; cat ' + POLICY + '; dmesg | tail -60')
            report['restored'] = True
        except Exception as error:
            report['cleanup_error'] = repr(error)
            failure = failure or error
        report['passed'] = report['matrix_passed'] and report['restored'] and failure is None
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if failure:
        raise failure
    print(json.dumps(dict(passed=report['passed'], packets=len(report['observations']), restored=report['restored'])))


if __name__ == '__main__':
    main()
