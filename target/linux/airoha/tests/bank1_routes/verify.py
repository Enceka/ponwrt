#!/usr/bin/env python3
"""Apply 991 to copied 987 driver files and exercise real route helpers with MMIO faults."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess


DRIVER = Path('drivers/net/ethernet/airoha')
FILES = ('airoha_eth.h', 'airoha_eth.c', 'airoha_ct_cpu_fallback.h',
         'airoha_ct_pon_ifc_cpu.h', 'airoha_ct_pair_banks.h', 'airoha_ct_pon_ifc_words.h',
         'airoha_ct_fe_native.h', 'airoha_ct_ifc_command.h')
FUNCTIONS = {
    'airoha_eth.c': ('airoha_set_gdm_port_fwd_cfg', 'airoha_dev_set_qdma'),
    'airoha_ct_pair_banks.h': ('airoha_ct_pair_gdm_route', 'airoha_ct_pair_gdm_start',
                              'airoha_ct_pair_gdm_stop'),
    'airoha_ct_fe_native.h': ('airoha_ct_fe_table',),
    'airoha_ct_pon_ifc_cpu.h': ('airoha_ct_pon_ifc_read', 'airoha_ct_pon_ifc_route_open'),
}


def extract_function(source, name):
    matches = list(re.finditer(r'^static [^;{}]*\b' + re.escape(name) + r'\([^;{}]*\)\n\{',
                               source, re.MULTILINE))
    if len(matches) != 1:
        raise ValueError('expected one function definition: ' + name)
    start = matches[0].start()
    opening = matches[0].end() - 1
    depth = 1
    end = opening + 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise ValueError('unterminated function: ' + name)
    return source[start:end] + '\n'


def run(command, output, label, env=None, cwd=None):
    result = subprocess.run(command, capture_output=True, text=True,
                            cwd=cwd or output, env=env)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ' failed:\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path,
                        default=repo.parent / 'pon-ifc-tuple-987-source',
                        help='Read-only kernel source through 987')
    parser.add_argument('--output', type=Path, default=tests / 'out')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--case', help='Run one named test group')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    if report_path.exists():
        report_path.unlink()
    patch = repo / ('target/linux/airoha/patches-6.18/'
                    '991-net-airoha-own-gdm-default-routes-for-bank1-isolation.patch')
    patch_bytes = patch.read_bytes()
    tree = output / 'kernel'
    driver = tree / DRIVER
    driver.mkdir(parents=True, exist_ok=True)
    originals = {}
    for name in FILES:
        originals[name] = (args.source.resolve() / DRIVER / name).read_bytes()
        (driver / name).write_bytes(originals[name])
    added = driver / 'airoha_bank1_routes.h'
    if added.exists():
        added.unlink()
    patch_output = run(['patch', '--batch', '--forward', '--fuzz=0',
                        '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                       output, 'apply', cwd=tree)
    if re.search(r'fuzz|offset|FAILED|reversed', patch_output, re.IGNORECASE):
        raise RuntimeError('991 must apply exactly to the 987 files:\n' + patch_output)
    modified = {name: (driver / name).read_bytes() for name in FILES + ('airoha_bank1_routes.h',)}
    header = modified['airoha_eth.h'].decode()
    layout = re.search(r'^struct airoha_bank1_routes \{\n.*?^\};', header, re.MULTILINE | re.DOTALL)
    if not layout or not re.search(r'struct airoha_bank1_routes\s+ct_bank1_routes;', header):
        raise RuntimeError('missing production bank1 route layout or eth field')
    (output / 'route_layout.inc').write_text(layout.group() + '\n')
    eth = modified['airoha_eth.c'].decode()
    if eth.index('#include "airoha_ct_cpu_fallback.h"') > eth.index('#include "airoha_bank1_routes.h"'):
        raise RuntimeError('guard must follow fallback in eth.c')
    extracted = {}
    for filename, names in FUNCTIONS.items():
        for name in names:
            extracted[name] = extract_function(modified[filename].decode(), name)
    (output / 'route_functions.inc').write_text('\n'.join(extracted.values()))
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError('compiler unavailable: ' + args.cc)
    version = run([compiler, '--version'], output, 'compiler')
    if 'clang' not in version.lower():
        raise RuntimeError('clang is required')
    build = [compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
             '-Wno-sign-compare',
             '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-fno-omit-frame-pointer', '-I', str(output), '-I', str(driver),
             str(tests / 'routes_test.c'), '-o', str(output / 'routes_test')]
    run(build, output, 'build')
    environment = dict(os.environ)
    environment['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1'
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    command = [str(output / 'routes_test')] + ([args.case] if args.case else [])
    result = run(command, output, 'routes_test', environment)
    if patch.read_bytes() != patch_bytes:
        raise RuntimeError('991 changed during testing; rerun against the completed patch')
    report = {
        'passed': True, 'case': args.case or 'all', 'source': str(args.source.resolve()),
        'compiler': version.splitlines()[0], 'sanitizers': ['address', 'undefined'],
        'sanitize_recover': False, 'patch_sha256': digest(patch_bytes),
        'base_sha256': {name: digest(data) for name, data in originals.items()},
        'source_sha256': {name: digest(data) for name, data in modified.items()},
        'extracted_sha256': {name: digest(data.encode()) for name, data in extracted.items()},
        'test_sha256': {name: digest((tests / name).read_bytes())
                        for name in ('verify.py', 'routes_test.c')},
        'result': result,
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(result)
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
