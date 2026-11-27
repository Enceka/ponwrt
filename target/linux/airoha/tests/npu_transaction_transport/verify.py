#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, output, name, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description='Apply 988 offline and test its real transports.')
    parser.add_argument('--source', type=Path, required=True,
                        help='Kernel source through 987; only airoha_npu.c is copied')
    parser.add_argument('--output', type=Path, required=True, help='New build output directory')
    parser.add_argument('--firmware', type=Path, help='Read-only firmware ABI reference')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--patch', default=os.environ.get('PATCH', 'patch'))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    patch = repo / ('target/linux/airoha/patches-6.18/'
                    '988-net-airoha-add-source-aware-npu-transaction-transport.patch')
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    relative = Path('drivers/net/ethernet/airoha')
    tree = output / 'kernel'
    driver = tree / relative
    driver.mkdir(parents=True)
    shutil.copyfile(source / relative / 'airoha_npu.c', driver / 'airoha_npu.c')
    patch_text = patch.read_text()
    assert patch_text.startswith('From: Enceka <enceka@yeah.net>\n')
    assert 'Signed-off-by:' not in patch_text
    applied = run([args.patch, '--batch', '--forward', '--fuzz=0',
                   '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                  output, 'apply', cwd=tree)
    assert 'fuzz' not in applied and 'offset' not in applied, applied
    implementation = driver / 'airoha_npu_transaction.inc'
    original = implementation.read_text()
    integration = (driver / 'airoha_npu.c').read_text()
    for suffix in ('auth', 'er', 'gate'):
        symbol = 'airoha_npu_' + suffix + '_command'
        assert 'EXPORT_SYMBOL_GPL(' + symbol + ');' in integration
        assert re.search(r'int\s+' + symbol + r'\(',
                         (driver / 'airoha_npu_transaction.h').read_text())
    assert '#include "airoha_npu_transaction.h"' in integration
    assert integration.index('static bool airoha_npu_wlan_short_guard_ready(') < \
        integration.index('#include "airoha_npu_transaction.inc"')
    assert 'airoha_eth_return.h' not in original
    abi_names = ['npu_auth_mailbox_abi.h', 'npu_eth_return_abi.h', 'npu_bank1_gate_abi.h']
    if args.firmware:
        for name in abi_names:
            assert (driver / name).read_bytes() == (args.firmware / 'include' / name).read_bytes(), name
    build = [args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-I', str(driver), str(tests / 'transport_test.c')]
    results = {}
    for mode, flags in [('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])]:
        binary = output / mode
        run(build + flags + ['-o', str(binary)], output, mode + '-build')
        results[mode] = run([str(binary)], output, mode)
    mutations = {
        'er_unknown_caps': ('caps != (ER_CAPS | ER_CAP_SOURCES)',
                            '!(caps & ER_CAP_SOURCES)'),
        'er_old_pon': ('sport != ER_PON || !(caps & ER_CAP_SOURCES)',
                       'sport != ER_PON'),
        'er_zero_query': ('discovery = op == ER_QUERY', 'discovery = op == ER_BIND'),
        'gate_mask_echo': ('words[GM_MASK] != requested', '0'),
        'gate_aggregate_limit': ('queued_max += ER_MAX_COUNT;', 'queued_max += 0;'),
        'gate_single_stopped': ('words[GM_CAPS] == GATE_CAPS ||', '1 ||'),
        'gate_dual_inactive': ('requested == (GATE_FE24 | GATE_PON2)', '0'),
        'auth_echo': ('memcmp(packet.data, reply, AM_STATUS * sizeof(*reply))', '0'),
    }
    mutation_results = {}
    for name, (before, after) in mutations.items():
        assert original.count(before) == 1, name
        implementation.write_text(original.replace(before, after))
        binary = output / name
        run(build + ['-o', str(binary)], output, name + '-build')
        result = subprocess.run([str(binary)], capture_output=True, text=True, cwd=output)
        implementation.write_text(original)
        (output / (name + '.log')).write_text(result.stdout + result.stderr)
        assert result.returncode != 0, 'missed mutation: ' + name
        mutation_results[name] = result.returncode
    report = {
        'passed': True,
        'source': str(source),
        'base_npu_sha256': digest(source / relative / 'airoha_npu.c'),
        'patch_sha256': digest(patch),
        'source_sha256': {name: digest(driver / name) for name in
                          abi_names + ['airoha_npu_transaction.h',
                                       'airoha_npu_transaction.inc', 'airoha_npu.c']},
        'test_sha256': digest(tests / 'transport_test.c'),
        'modes': results,
        'caught_mutations': mutation_results,
        'firmware_abi_match': bool(args.firmware),
        'exports': ['airoha_npu_' + suffix + '_command' for suffix in ('auth', 'er', 'gate')],
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
