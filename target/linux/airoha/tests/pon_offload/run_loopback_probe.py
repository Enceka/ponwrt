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
    parser.add_argument('--pin', type=Path, required=True)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--module', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--special-tag', action='store_true')
    args = parser.parse_args()
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

    before, _ = remote('before', 'cat /sys/kernel/debug/gpio; cat ' + classifier +
                       '; cat /sys/kernel/debug/ppe/config; ip -d link show pon0')
    assert re.search(r'ram-pon-tx-disable[^\n]*out hi', before)
    assert 'saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0' in before
    assert 'ct_cpu_fallback: 0 ' in before
    assert 'state DOWN' in before
    report = {'boot': args.boot, 'module_sha256': args.sha256, 'special_tag': args.special_tag,
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
        write('classify-a', classifier, 'set 0 0x2134')
        write('classify-b', classifier, 'set 1 0xa134')
        remote('classified', 'cat ' + classifier + '; cat /sys/kernel/debug/ppe/config')
        for index, service in enumerate((0x2134, 0xa134, 0x2134)):
            label = 'send-' + str(index)
            sent, status = remote(label, 'echo ' + shlex.quote('send ' + str(service)) +
                                  ' > ' + probe + 'command', check=False)
            observed, _ = remote(label + '-observed', 'cat ' + probe + 'status; cat ' + classifier)
            fields = dict(re.findall(r'(\w+)=([0-9a-f]+)', observed.splitlines()[0]))
            returned_service = (int(fields['rx_msg0'], 16) >> 14) & 0xffff
            returned_source = (int(fields['rx_msg1'], 16) >> 21) & 31
            numbered_return = int(fields['received']) == index + 1 and int(fields['rx_sequence']) == index + 1
            report['observations'].append({'service': service, 'command_status': status,
                                          'returned_service': returned_service, 'returned_source': returned_source,
                                          'numbered_return': numbered_return, 'state': observed})
            if status:
                raise RuntimeError(label + ' failed; see recorded status')
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
            report['registers_restored'] = True
            remote('unload', 'rmmod ct_pon_loopback')
        remote('ipv6-restore', 'echo ' + ipv6_state.strip() + ' > /proc/sys/net/ipv6/conf/pon0/disable_ipv6')
        after, _ = remote('after', 'cat /sys/kernel/debug/ppe/config; cat ' + classifier +
                          '; cat /sys/bus/platform/devices/1fb50000.ethernet/ct_native_pair_policy; dmesg | tail -45')
        assert 'ct_cpu_fallback: 0 ' in after
        assert 'saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0' in after
        assert re.search(r'^generation=\d+ allowed=\d+ failed=0$', after, re.M)
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    assert report['numbered_packets_returned'], 'numbered loopback packets missing'
    if args.special_tag:
        assert report['service_preserved'], 'special tag service mismatch'
    print(json.dumps({'commands_completed': report.get('commands_completed', False),
                      'registers_restored': report.get('registers_restored', False), 'output': str(output)}))


if __name__ == '__main__':
    main()
