#!/usr/bin/env python3
"""Replay ZZ9 exactly and exercise the real FLOW_CLS_STATS dispatch."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks

DRIVER = Path('drivers/net/ethernet/airoha')
PATCH = '999-zz9-net-airoha-report-pon-session-activity.patch'
TARGETS = ('airoha_npu_production.h', 'airoha_ppe.c')


def block(source, pattern, semicolon=False):
    matches = list(re.finditer(pattern, source, re.M))
    assert len(matches) == 1, pattern
    start = matches[0].start()
    position = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[position] == '{') - (source[position] == '}')
        position += 1
    if semicolon:
        assert source[position] == ';'
        position += 1
    return source[start:position] + '\n'


def function(source, name):
    return block(source, r'^(?:static )?[^;{}\n]+\b' + name + r'\([^;{}]*\)\n\{')


def abi(source):
    pieces = [block(source, r'^enum[^\n{]*\{(?=\s*' + marker + r'\b)', True)
              for marker in ('AIROHA_FOE_STATE_INVALID', 'PPE_PKT_TYPE_IPV4_HNAPT',
                             'AIROHA_DEV_F_WAN', 'FLOW_TYPE_L4')]
    pieces += [line + '\n' for line in source.splitlines()
               if re.match(r'#define (?:AIROHA_FOE_IB1_\w+|AIROHA_PON_QDMA_\w+|PPE_ENTRY_SIZE)\b', line)]
    names = ('airoha_foe_mac_info_common', 'airoha_foe_mac_info', 'airoha_foe_bridge',
             'airoha_foe_l2b', 'airoha_foe_ipv4_tuple', 'airoha_foe_ipv4',
             'airoha_foe_ipv4_dslite', 'airoha_foe_ipv6', 'airoha_foe_entry',
             'airoha_foe_stats64', 'airoha_ct_bridge_peer', 'airoha_pon_unbound_event',
             'airoha_flow_table_entry', 'airoha_pon_flow_entry', 'airoha_pon_flow_table',
             'airoha_pon_candidate_snapshot')
    pieces += [block(source, r'^struct ' + name + r'\s*(?=\{)', True) for name in names]
    pieces += [line + '\n' for line in source.splitlines() if line.startswith('static_assert(')]
    return '\n'.join(pieces)


def prepare(args, output):
    baseline = args.baseline.resolve()
    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    patch = binding.snapshot[PATCH]
    assert patch.decode().startswith('From: Enceka <enceka@yeah.net>\n')
    names = re.findall(r'^\+\+\+ b/(.+)$', patch.decode(), re.M)
    assert set(names) == {str(DRIVER / name) for name in TARGETS}
    assert len(names) == len(TARGETS)
    kernel = output / 'kernel'
    driver = kernel / DRIVER
    shutil.copytree(baseline / DRIVER, driver)
    inputs = {path: path.read_bytes() for path in (baseline / DRIVER).iterdir() if path.is_file()}
    inputs.update({path: path.read_bytes() for path in HERE.iterdir() if path.is_file()})
    inputs[binding.patches / PATCH] = patch
    sections = list(binding.sections(patch, TARGETS))
    assert len(sections) == len(TARGETS)
    for name, added, section in sections:
        assert not added
        exact_hunks((driver / name).read_bytes(), section)
    patch_file = output / PATCH
    patch_file.write_bytes(patch)
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0',
                             '--no-backup-if-mismatch', '-p1', '-d', str(kernel),
                             '-i', str(patch_file)], capture_output=True, text=True,
                            check=True, timeout=30)
    assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    if args.source:
        for path in driver.iterdir():
            if not path.is_file():
                continue
            applied = args.source.resolve() / DRIVER / path.name
            inputs[applied] = applied.read_bytes()
            assert path.read_bytes() == inputs[applied], 'source differs from ZZ9 replay: ' + path.name
    print('binding: complete ZZ9 replay with exact hunk positions and context', flush=True)
    print('PATCH sha256=' + hashlib.sha256(patch).hexdigest(), flush=True)
    return driver, inputs


def exercise(args, output, driver):
    ppe = (driver / 'airoha_ppe.c').read_text()
    production = (driver / 'airoha_npu_production.h').read_text()
    owners = (driver / 'airoha_npu_owner.h').read_text()
    replacements = {
        '@ABI@': abi((driver / 'airoha_eth.h').read_text()),
        '@PRODUCTION_ACTIVE@': function(owners, 'airoha_ppe_npu_production_active'),
        '@CANDIDATE_FUNCTIONS@': '\n'.join(function(ppe, name) for name in (
            'airoha_ppe_foe_compare_entry', 'airoha_ppe_ct_pon_row_matches',
            'airoha_ppe_ct_pon_dev_ready', 'airoha_ppe_pon_candidate_read_locked',
            'airoha_ppe_pon_candidate_validate')),
        '@VALIDATE@': function(production, 'airoha_npu_production_validate'),
        '@IDLE_TIME@': function(ppe, 'airoha_ppe_get_entry_idle_time'),
        '@ACTIVITY@': function(production, 'airoha_npu_production_idle'),
        '@STATS@': function(ppe, 'airoha_ppe_flow_offload_stats'),
        '@COMMAND@': function(ppe, 'airoha_ppe_flow_offload_cmd'),
    }
    source = (HERE / 'activity_test.c').read_text()
    for marker, content in replacements.items():
        assert source.count(marker) == 1, marker
        source = source.replace(marker, content)
    environment = {**os.environ, 'ASAN_OPTIONS': 'halt_on_error=1:abort_on_error=1',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    for label, flags in (('plain', []), ('sanitized', ['-fsanitize=address,undefined',
                                                    '-fno-sanitize-recover=all'])):
        binary = output / label
        command = [args.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter', '-I', str(driver), *flags,
                   '-x', 'c', '-', '-o', str(binary)]
        subprocess.run(command, input=source, text=True, check=True, timeout=60)
        result = subprocess.run([binary], capture_output=True, text=True,
                                env=environment, timeout=60)
        if result.returncode:
            raise RuntimeError(label + ':\n' + result.stdout + result.stderr)
        print(label + ': ' + result.stdout.strip(), flush=True)
    for marker, content in replacements.items():
        print(marker.strip('@') + ' sha256=' + hashlib.sha256(content.encode()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True,
                        help='Kernel source immediately before ZZ9')
    parser.add_argument('--source', type=Path,
                        help='Optionally compare the full applied driver directory')
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='.run-', dir=HERE) as temp:
        output = Path(temp)
        driver, inputs = prepare(args, output)
        exercise(args, output, driver)
        for path, original in inputs.items():
            assert path.read_bytes() == original, 'input changed during test: ' + str(path)


if __name__ == '__main__':
    main()
