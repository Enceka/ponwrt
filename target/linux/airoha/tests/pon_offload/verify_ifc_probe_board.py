#!/usr/bin/env python3
"""Exercise the RAM-only optical CPU classifier through its kernel owner."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import uuid


PROBE = '/sys/bus/platform/devices/1fb50000.ethernet/ct_pon_cpu_probe'
CONFIG = '/sys/kernel/debug/ppe/config'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pin', required=True, type=Path)
    parser.add_argument('--boot', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--identity', type=Path)
    parser.add_argument('--interface', default='en6', choices=['en6'])
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    uuid.UUID(args.boot)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
           '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(args.pin.resolve()),
           '-o', 'ProxyCommand=/usr/bin/nc -4 -b ' + args.interface + ' -G 4 %h %p']
    if args.identity:
        ssh += ['-i', str(args.identity.resolve())]
    ssh += ['root@192.168.1.1']
    guard = ('set -eu; test "$(cat /proc/sys/kernel/random/boot_id)" = ' + shlex.quote(args.boot) +
             '; test "$(wc -l </proc/mtd)" = 1; ')
    steps = []

    def remote(command, label, expected=0):
        result = subprocess.run(ssh + [guard + command], text=True, capture_output=True, timeout=20)
        (output / (label + '.stdout')).write_text(result.stdout)
        (output / (label + '.stderr')).write_text(result.stderr)
        (output / (label + '.status.json')).write_text(json.dumps({'returncode': result.returncode}) + '\n')
        if expected == 0:
            result.check_returncode()
        else:
            assert result.returncode not in (0, 255), (label, result.returncode, result.stderr)
        return result.stdout

    def state(label, active, services):
        text = remote('cat ' + PROBE + '; cat ' + CONFIG, label)
        first, config = text.split('\n', 1)
        fields = dict(item.split('=', 1) for item in first.split())
        expected = {'saved': int(bool(active)), 'dirty': active, 'active': active,
                    'pending': 0, 'scope': 0x1000004 if active else 0x1000000,
                    'ready': int(bool(active)), 'service0': services[0],
                    'service1': services[1], 'ppe': 0, 'errors': 0}
        for key, value in expected.items():
            assert int(fields[key], 16 if key in ('dirty', 'active', 'scope') else 10) == value, (label, first)
        assert re.search(r'^ct_cpu_fallback: 0 ', config, re.M), (label, config)
        assert re.search(r'^fe_ifc_port_en: %08x$' % expected['scope'], config, re.M), (label, config)
        assert re.search(r'^gdm2_fwd_cfg: 07f15555(?: fallback_mask: 0000)?$', config, re.M), (label, config)
        steps.append({'label': label, 'state': fields})
        return config

    before = state('before', 0, (0, 0))
    remote('cat /proc/mtd; cat /sys/kernel/debug/gpio; ip link show pon0; '
           'cat /sys/bus/platform/devices/1fa03000.wireless-offload/status', 'platform-before')
    if not args.run:
        print(json.dumps({'preflight': True, 'boot': args.boot, 'output': str(output)}))
        return
    try:
        for cycle in range(3):
            prefix = str(cycle) + '-'
            for label, command, active, services in [
                ('set-a', 'set 0 0x2134', 3, (0x2134, 0)),
                ('set-b', 'set 1 0x3579', 15, (0x2134, 0x3579)),
                ('replace-a', 'set 0 0x1122', 15, (0x1122, 0x3579)),
                ('clear-a', 'clear 0', 12, (0, 0x3579)),
                ('clear-b', 'clear 1', 0, (0, 0)),
            ]:
                remote('printf "%s\\n" ' + shlex.quote(command) + ' > ' + PROBE, prefix + label + '-write')
                state(prefix + label, active, services)
                if label == 'set-b':
                    remote('printf "%s\\n" "set 0 0x3579" > ' + PROBE, prefix + 'duplicate', expected=1)
                    state(prefix + 'duplicate-unchanged', active, services)
        for label, command, active, services in [
            ('off-set-a', 'set 0 0x2134', 3, (0x2134, 0)),
            ('off-set-b', 'set 1 0x3579', 15, (0x2134, 0x3579)),
            ('off', 'off', 0, (0, 0)),
        ]:
            remote('printf "%s\\n" ' + shlex.quote(command) + ' > ' + PROBE, label + '-write')
            state(label, active, services)
        after = state('after', 0, (0, 0))
        assert before == after
    finally:
        remote('printf "%s\\n" off > ' + PROBE, 'cleanup')
    remote('dmesg; ip -4 route; iw dev', 'platform-after')
    report = {'passed': True, 'boot': args.boot, 'cycles': 3,
              'kernel_write_readback': True, 'hardware_config_restored': True,
              'optical_packet_acceptance': False, 'steps': steps}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': True, 'boot': args.boot, 'cycles': 3, 'output': str(output)}))


if __name__ == '__main__':
    main()
