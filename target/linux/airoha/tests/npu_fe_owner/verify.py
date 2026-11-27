#!/usr/bin/env python3
"""Apply 992 to read-only sources and compile the real native FE/pair C."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess


DRIVER = Path('drivers/net/ethernet/airoha')
HEADERS = ('airoha_eth.h', 'airoha_ct_fe_native.h', 'airoha_ct_native_pair.h',
           'airoha_ct_pair_policy.h', 'airoha_ct_ifc_command.h')
EXTRA = ('include/linux/soc/airoha/airoha_offload.h', 'include/net/cfg80211.h',
         'net/bridge/br_switchdev.c', 'net/bridge/br_forward.c')


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1] + '\n'
    raise ValueError('unterminated function: ' + signature)


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('fixture changed: ' + old[:100])
    return source.replace(old, new, 1)


def execute(command, output, label, cwd=None):
    result = subprocess.run(command, cwd=cwd or output, text=True, capture_output=True)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ' failed:\n' + result.stdout + result.stderr)
    return result.stdout


def main():
    tests = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, help='Local kernel tree through 991')
    parser.add_argument('--vm-source', default='/workdir/pon-npu-989')
    parser.add_argument('--vm', default='ponwrt')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--output', type=Path, default=tests / 'out')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = output / 'report.json'
    report.unlink(missing_ok=True)
    patch = tests.parents[1] / ('patches-6.18/'
                              '992-net-airoha-arbitrate-native-fe-lifecycle-ownership.patch')
    patch_bytes = patch.read_bytes()
    sources = {}
    for relative in tuple(str(DRIVER / name) for name in HEADERS) + EXTRA:
        if args.source:
            data = (args.source.resolve() / relative).read_bytes()
        else:
            data = subprocess.run(['orb', '-m', args.vm, 'cat',
                                   args.vm_source.rstrip('/') + '/' + relative],
                                  capture_output=True, check=True).stdout
        sources[relative] = data
    tree = output / 'kernel'
    driver = tree / DRIVER
    driver.mkdir(parents=True, exist_ok=True)
    for name in HEADERS:
        (driver / name).write_bytes(sources[str(DRIVER / name)])
    applied = execute(['patch', '--batch', '--forward', '--fuzz=0',
                       '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                      output, 'apply', cwd=tree)
    if re.search(r'fuzz|offset|FAILED|reversed', applied, re.IGNORECASE):
        raise RuntimeError('992 requires exact baseline context:\n' + applied)
    modified = {name: (driver / name).read_text() for name in HEADERS}
    layout = modified['airoha_eth.h']
    match = re.search(r'\tstruct \{\n\t\tconst void \*owner;.*?\n\t\} ct_fe;',
                      layout, re.DOTALL)
    if not match:
        raise ValueError('missing production FE owner layout')
    (output / 'fe_layout.inc').write_text(match.group() + '\n')
    (output / 'foe_layout.inc').write_text(
        layout[layout.index('enum {\n\tAIROHA_FOE_STATE_INVALID,'):
               layout.index('struct airoha_foe_stats {')])
    abi = sources[EXTRA[0]].decode()
    (output / 'pair_abi.inc').write_text(
        abi[abi.index('/* Native endpoint pair ABI'):abi.index('struct airoha_npu {')])
    (output / 'wiphy_dev.inc').write_text(function(
        sources[EXTRA[1]].decode(), 'static inline struct device *wiphy_dev('))
    bridge = sources[EXTRA[2]].decode()
    (output / 'bridge_fdb_lookup.inc').write_text(
        function(bridge, 'static bool br_switchdev_fdb_notifies(') +
        function(bridge, 'struct net_device *br_switchdev_fdb_find_port('))
    forward = sources[EXTRA[3]].decode()
    (output / 'bridge_frame_notify.inc').write_text(
        forward[forward.index('\tif (netif_is_bridge_port(skb->dev) && skb->skb_iif &&'):
                forward.index('\tdev_queue_xmit(skb);')])
    for name in HEADERS[1:]:
        (output / name).write_text(modified[name])
    policy = modified['airoha_ct_pair_policy.h']
    (output / 'pair_policy_event.inc').write_text(function(
        policy, 'static int airoha_ct_pair_policy_event('))
    (output / 'policy_store.inc').write_text(function(
        policy, 'static ssize_t ct_native_pair_policy_store('))
    legacy_path = tests.parent / 'native_pair/verify_pair.c'
    legacy = legacy_path.read_text()
    prefix = legacy[:legacy.index('#include "airoha_ct_native_pair.h"')]
    fixture = legacy[legacy.index('static struct airoha_ct_native_pair pairs[32];'):
                     legacy.index('int main(void)')]
    prefix = replace_once(prefix, 'u32 ct_pair_token,ct_wlan_epoch',
                          '\n#include "fe_layout.inc"\n'
                          'struct {struct {u8 lut_index;} rule[2];} ct_ifc;\n'
                          'bool ct_pair_close_pending;\nu32 ct_pair_token,ct_wlan_epoch')
    prefix = replace_once(prefix, 'struct airoha_eth {',
                          'struct airoha_eth {struct airoha_ppe *ppe;'
                          'bool ct_ifc_cpu_port_failed,ct_cpu_fallback,'
                          'ct_cpu_ifc_disabled,ct_cpu_routes_ready,ct_cpu_wlan_gated,'
                          'ct_ifc_command_pending;')
    prefix = replace_once(prefix, 'static int mock_send(', 'static int original_mock_send(')
    fixture = replace_once(fixture, 'static void reset(void){', 'static void base_reset(void){')
    combined = ('struct work_struct {int unused;};\n'
                'struct delayed_work {struct work_struct work;};\n' + prefix +
                '\n#include "stubs.inc"\n#include "airoha_ct_native_pair.h"\n'
                '#include "pair_policy_event.inc"\n' + fixture +
                '\n#include "owner_test.c"\n')
    (output / 'test.c').write_text(combined)
    compile_command = [args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                       '-Wno-unused-parameter', '-Wno-unused-function', '-O1', '-g',
                       '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                       '-fno-omit-frame-pointer', '-I' + str(output), '-I' + str(tests),
                       str(output / 'test.c'), '-o', str(output / 'test')]
    execute(compile_command, output, 'build')
    result = execute([str(output / 'test')], output, 'test')
    if patch.read_bytes() != patch_bytes:
        raise RuntimeError('992 changed during testing; rerun')
    digest = lambda data: hashlib.sha256(data).hexdigest()
    report.write_text(json.dumps({
        'passed': True, 'result': result.strip(),
        'source': str(args.source) if args.source else args.vm + ':' + args.vm_source,
        'sanitizers': ['address', 'undefined'], 'patch_sha256': digest(patch_bytes),
        'baseline_sha256': {name: digest(data) for name, data in sources.items()},
        'production_sha256': {name: digest(text.encode()) for name, text in modified.items()},
        'fixture_sha256': digest(legacy.encode()),
        'test_sha256': {name: digest((tests / name).read_bytes())
                        for name in ('verify.py', 'stubs.inc', 'owner_test.c')},
    }, indent=2) + '\n')
    print(result.strip())
    print('report: ' + str(report))


if __name__ == '__main__':
    main()
