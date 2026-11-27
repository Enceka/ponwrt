#!/usr/bin/env python3
"""Run the bounded RAM optical loopback experiment and preserve observations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error('Run without -O; hardware validation requires assertions.')
    parser.add_argument('--pin', type=Path, required=True)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--special-tag', action='store_true')
    parser.add_argument('--cover-slot', type=int, choices=(0, 1))
    parser.add_argument('--withdraw-cycle', action='store_true')
    parser.add_argument('--sif-sweep', action='store_true')
    parser.add_argument('--sif-mode', choices=('source', 'absent', 'only'), default='source')
    parser.add_argument('--packet-matrix', action='store_true')
    parser.add_argument('--require-native', action='store_true')
    parser.add_argument('--tuple-variants', action='store_true')
    parser.add_argument('--exact-tuple', action='store_true',
                        help='Use kernel987 tuple classification with --tuple-variants --cover-slot 1')
    args = parser.parse_args()
    if args.cover_slot is not None and not args.special_tag:
        parser.error('--cover-slot requires --special-tag')
    if args.withdraw_cycle and args.cover_slot is None:
        parser.error('--withdraw-cycle requires --cover-slot')
    if args.sif_sweep and (args.cover_slot != 1 or args.withdraw_cycle):
        parser.error('--sif-sweep requires --cover-slot 1 without --withdraw-cycle')
    if args.packet_matrix and (args.cover_slot != 1 or args.withdraw_cycle or args.sif_sweep):
        parser.error('--packet-matrix requires --cover-slot 1 without other experiments')
    if args.tuple_variants and (args.cover_slot != 1 or args.sif_sweep or args.packet_matrix or
                                (args.withdraw_cycle and not args.exact_tuple)):
        parser.error('--tuple-variants requires --cover-slot 1; withdrawal requires --exact-tuple')
    if args.exact_tuple and (not args.tuple_variants or args.cover_slot != 1):
        parser.error('--exact-tuple requires --tuple-variants and --cover-slot 1')
    uuid.UUID(args.boot)
    blob = args.module.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == args.sha256
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(args.pin.resolve()),
           '-o', 'ProxyCommand=/usr/bin/nc -4 -b en6 -G 4 %h %p']
    if args.identity:
        ssh += ['-i', str(args.identity.resolve())]
    ssh += ['root@192.168.1.1']
    guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(args.boot) +
             '; test "$(wc -l </proc/mtd)" = 1; ')
    probe = '/sys/kernel/debug/ct_pon_loopback/'
    classifier = '/sys/bus/platform/devices/1fb50000.ethernet/ct_pon_cpu_probe'

    def remote(label, command, data=None, check=True):
        result = subprocess.run(ssh + [guard + command], input=data, capture_output=True, timeout=25)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        (output / (label + '.status.json')).write_text(json.dumps({'returncode': result.returncode}) + '\n')
        if check:
            result.check_returncode()
        return result.stdout.decode(), result.returncode

    def write(label, path, command):
        return remote(label, 'echo ' + shlex.quote(command) + ' > ' + path)

    def check_tuple_pool(state, owned):
        pool = re.search(r'\btuple=(\d+) pool=([0-9a-f]{8}) pool_pending=(\d+) leases=(\d+)\b', state)
        assert pool, 'tuple pool status missing'
        mask = int(pool[2], 16)
        assert (int(pool[1]), int(pool[3]), int(pool[4]), bin(mask).count('1')) == (
            (1, 0, 2, 14) if owned else (0, 0, 0, 0)), 'tuple pool ownership mismatch'
        assert re.search(r'\bppe=0\b', state), 'PON PPE qualification must stay closed'
        return mask

    before, _ = remote('before', 'cat /sys/kernel/debug/gpio; cat ' + classifier +
                       '; cat /sys/kernel/debug/ppe/config; ip -d link show pon0; cat ' +
                       '/sys/bus/platform/devices/1fb50000.ethernet/ct_native_pair_policy')
    assert re.search(r'ram-pon-tx-disable[^\n]*out hi', before)
    assert 'saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0' in before
    assert 'ct_cpu_fallback: 0 ' in before
    assert 'state DOWN' in before
    tuple_clean = 'tuple=0 pool=00000000 pool_pending=0 leases=0'
    if args.exact_tuple:
        assert tuple_clean in before, 'tuple pool is not idle'
    policy_pattern = r'^generation=\d+ allowed=' + ('1' if args.require_native else r'\d+') + r' failed=0$'
    assert re.search(policy_pattern, before, re.M)
    report = {'boot': args.boot, 'module_sha256': args.sha256, 'special_tag': args.special_tag,
              'cover_slot': args.cover_slot, 'sif_sweep': args.sif_sweep,
              'withdraw_cycle': args.withdraw_cycle,
              'tuple_variants': args.tuple_variants, 'exact_tuple': args.exact_tuple,
              'require_native': args.require_native,
              'observations': []}
    if not args.run:
        print(json.dumps({'preflight': True, 'output': str(output)}))
        return
    loaded = False
    baseline = ''
    ipv6_state, _ = remote('ipv6-before', 'cat /proc/sys/net/ipv6/conf/pon0/disable_ipv6')
    assert ipv6_state.strip() in ('0', '1')
    try:
        remote('ipv6-disable', 'echo 1 > /proc/sys/net/ipv6/conf/pon0/disable_ipv6')
        remote('upload', 'test ! -d /sys/module/ct_pon_loopback; cat > /tmp/ct_pon_loopback.ko', blob)
        remote('load', 'test "$(sha256sum /tmp/ct_pon_loopback.ko | cut -d " " -f1)" = ' +
               shlex.quote(args.sha256) + '; insmod /tmp/ct_pon_loopback.ko special_tag=' + str(int(args.special_tag)))
        loaded = True
        baseline, _ = remote('baseline', 'cat ' + probe + 'status')
        write('prepare', probe + 'command', 'prepare')
        remote('prepared', 'cat ' + probe + 'status; cat /sys/kernel/debug/ppe/config')
        if args.cover_slot is None:
            write('classify-a', classifier, 'set 0 0x2134')
            write('classify-b', classifier, 'set 1 0xa134')
        else:
            write('cover', classifier, 'cover ' + str(args.cover_slot))
            classify_command = 'tuple' if args.exact_tuple else 'set'
            write('classify-a', classifier, classify_command + ' ' + str(args.cover_slot ^ 1) + ' 0x2134')
            write('route', classifier, 'route')
        classified, _ = remote('classified', 'cat ' + classifier + '; cat /sys/kernel/debug/ppe/config')
        if args.exact_tuple:
            tuple_owned = True
            tuple_mask = check_tuple_pool(classified, tuple_owned)
            assert 'active=0f' in classified
        cover_ring = 2 + 2 * (args.cover_slot or 0)
        cases = [(service, (), True, 2 if service == 0x2134 else cover_ring)
                 for service in (0x2134, 0xa134, 0x2134)]
        if args.sif_sweep:
            cases = [(0x2134, (args.sif_mode + ' ' + str(source), 'route'), True, None)
                     for source in range(32)]
        if args.withdraw_cycle and not args.exact_tuple:
            cases += [
                (0x2134, ('clear ' + str(args.cover_slot ^ 1), 'route'), True, cover_ring),
                (0xa134, (), True, cover_ring),
                (0x2134, ('set ' + str(args.cover_slot ^ 1) + ' 0x2134', 'route'), True, 2),
                (0xa134, ('clear ' + str(args.cover_slot),), False, 0),
                (0x2134, ('clear ' + str(args.cover_slot ^ 1),), False, 0),
            ]
        cases = [(service, commands, routed, 'ipv4', 0, expected_ring)
                 for service, commands, routed, expected_ring in cases]
        if args.packet_matrix:
            cases = [(service, (), True, kind, 0,
                      2 if kind in ('ipv4', 'ipv6', 'fragment') and service == 0x2134 else 4)
                     for kind in ('ipv4', 'ipv6', 'arp', 'vlan', 'pppoe', 'fragment', 'short')
                     for service in (0x2134, 0xa134)]
        if args.tuple_variants:
            cases = [(service, (), True, kind, variant,
                      2 if service == 0x2134 and (not args.exact_tuple or variant == 0) else 4)
                     for kind in ('ipv4', 'ipv6') for variant in range(5)
                     for service in (0x2134, 0xa134)]
        if args.exact_tuple and args.withdraw_cycle:
            cases += [
                (0x2134, ('clear 0', 'route'), True, 'ipv4', 0, 4),
                (0x2134, ('tuple 0 0x2134', 'route'), True, 'ipv4', 0, 2),
                (0x2134, ('clear 1',), False, 'ipv4', 0, 0),
                (0x2134, ('clear 0',), False, 'ipv4', 0, 0),
            ]
        for index, (service, commands, routed, kind, variant, expected_ring) in enumerate(cases):
            label = 'send-' + str(index)
            for step, command in enumerate(commands):
                transition = label + '-transition-' + str(step)
                write(transition, classifier, command)
                if args.exact_tuple:
                    if command == 'clear 0':
                        tuple_owned, tuple_mask = False, 0
                    elif command.startswith('tuple '):
                        tuple_owned, tuple_mask = True, None
                    state, _ = remote(transition + '-state', 'cat ' + classifier + '; cat /sys/kernel/debug/ppe/config')
                    actual_mask = check_tuple_pool(state, tuple_owned)
                    assert tuple_mask is None or actual_mask == tuple_mask, 'tuple pool mask changed'
                    tuple_mask = actual_mask
            previous, _ = remote(label + '-before', 'cat ' + probe + 'status')
            command = 'send ' + str(service)
            if args.packet_matrix or args.tuple_variants:
                command += ' ' + kind
            if args.tuple_variants:
                command += ' ' + str(variant)
            sent, status = remote(label, 'echo ' + shlex.quote(command) +
                                  ' > ' + probe + 'command', check=False)
            observed, _ = remote(label + '-observed', 'cat ' + probe + 'status; cat ' + classifier +
                                 '; cat /sys/kernel/debug/ppe/config; cat ' +
                                 '/sys/bus/platform/devices/1fb50000.ethernet/ct_native_pair_policy')
            fields = dict(re.findall(r'(\w+)=([0-9a-f]+)', observed.splitlines()[0]))
            returned_service = (int(fields['rx_msg0'], 16) >> 14) & 0xffff
            returned_source = (int(fields['rx_msg1'], 16) >> 21) & 31
            numbered_return = int(fields['received']) == index + 1 and int(fields['rx_sequence']) == index + 1
            before_heads = dict(re.findall(r'^rx(\d+) head=(\d+)', previous, re.M))
            after_heads = dict(re.findall(r'^rx(\d+) head=(\d+)', observed, re.M))
            changed_rings = [int(ring) for ring in before_heads if before_heads[ring] != after_heads[ring]]
            report['observations'].append({'service': service, 'command_status': status,
                                          'kind': kind, 'variant': variant,
                                          'returned_service': returned_service, 'returned_source': returned_source,
                                          'numbered_return': numbered_return, 'changed_rings': changed_rings,
                                          'transitions': commands, 'state': observed})
            if args.cover_slot is not None:
                report['observations'][-1]['expected_ring'] = expected_ring
            if status:
                raise RuntimeError(label + ' failed; see recorded status')
            assert 'ct_cpu_fallback: 0 ' in observed
            assert re.search(policy_pattern, observed, re.M)
            if args.cover_slot is not None:
                assert numbered_return and 'routed=' + str(int(routed)) in observed
                assert len(changed_rings) == 1, 'expected a covered WAN CPU receive ring'
                if expected_ring is not None:
                    assert changed_rings == [expected_ring], (kind + ' variant ' + str(variant) +
                                                              ' service ' + hex(service) +
                                                              ' expected RX' + str(expected_ring))
                else:
                    assert changed_rings[0] in (2, 4)
                if args.exact_tuple:
                    assert check_tuple_pool(observed, tuple_owned) == tuple_mask, 'tuple pool mask changed'
                if args.tuple_variants:
                    assert 'tx_variant=' + str(variant) in observed
                    assert 'tx_kind=' + kind in observed and 'rx_kind=' + kind in observed
                elif args.packet_matrix:
                    assert 'tx_kind=' + kind in observed and 'rx_kind=' + kind in observed
        report['commands_completed'] = True
        report['numbered_packets_returned'] = all(item['numbered_return'] for item in report['observations'])
        report['service_preserved'] = all(item['returned_service'] == item['service'] and
                                         item['returned_source'] == 2 for item in report['observations'])
    finally:
        if loaded:
            write('classifier-off', classifier, 'off')
            write('restore', probe + 'command', 'restore')
            restored, _ = remote('restored', 'cat ' + probe + 'status; cat ' + classifier)
            assert restored.startswith('retained=0 controller=0 opened=0 saved=0 error=0 pending=0 ')
            initial_regs = re.findall(r'^([0-9a-f]{4})=([0-9a-f]{8}) ', baseline, re.M)
            final_regs = re.findall(r'^([0-9a-f]{4})=([0-9a-f]{8}) ', restored, re.M)
            assert initial_regs == final_regs and len(initial_regs) == 10
            if args.exact_tuple:
                assert tuple_clean in restored, 'tuple pool was not released'
                report['tuple_pool_released'] = True
            report['registers_restored'] = True
            remote('unload', 'rmmod ct_pon_loopback')
        remote('ipv6-restore', 'echo ' + ipv6_state.strip() + ' > /proc/sys/net/ipv6/conf/pon0/disable_ipv6')
        after, _ = remote('after', 'cat /sys/kernel/debug/ppe/config; cat ' + classifier +
                          '; cat /sys/bus/platform/devices/1fb50000.ethernet/ct_native_pair_policy; dmesg | tail -45')
        assert 'ct_cpu_fallback: 0 ' in after
        assert 'saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0' in after
        if args.exact_tuple:
            assert tuple_clean in after, 'tuple pool is not idle after cleanup'
        assert re.search(policy_pattern, after, re.M)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['numbered_packets_returned'], 'numbered loopback packets missing'
    if args.special_tag:
        assert report['service_preserved'], 'special tag service mismatch'
    print(json.dumps({'commands_completed': report.get('commands_completed', False),
                      'registers_restored': report.get('registers_restored', False), 'output': str(output)}))


if __name__ == '__main__':
    main()
