#!/usr/bin/env python3
"""Compile the real 990 transaction core with the three real 988 ABI headers."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess


DRIVER = 'drivers/net/ethernet/airoha/'
CORE = 'airoha_npu_transaction_core.h'
ABIS = ('npu_auth_mailbox_abi.h', 'npu_bank1_gate_abi.h', 'npu_eth_return_abi.h')


def added_file(patch, name):
    marker = '--- /dev/null\n+++ b/' + DRIVER + name + '\n'
    if patch.count(marker) != 1:
        raise ValueError('expected one complete new file: ' + name)
    lines = patch.split(marker, 1)[1].splitlines(keepends=True)
    match = re.fullmatch(r'@@ -0,0 \+1,(\d+) @@\n', lines[0])
    if not match:
        raise ValueError('expected complete addition hunk: ' + name)
    count = int(match.group(1))
    body = lines[1:count + 1]
    if len(body) != count or any(not line.startswith('+') for line in body):
        raise ValueError('invalid addition hunk: ' + name)
    if len(lines) > count + 1 and lines[count + 1].startswith(('+', '@@')):
        raise ValueError('addition hunk length mismatch: ' + name)
    return ''.join(line[1:] for line in body).encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def execute(command, output, label, env=None):
    result = subprocess.run(command, capture_output=True, text=True, cwd=output, env=env)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ' failed:\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    tests = Path(__file__).resolve().parent
    patches = tests.parents[1] / 'patches-6.18'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=tests / 'out')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    if report_path.exists():
        report_path.unlink()
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError('compiler unavailable: ' + args.cc)
    version = execute([compiler, '--version'], output, 'compiler')
    if 'clang' not in version.lower():
        raise RuntimeError('this runner requires clang')
    patch_paths = {
        '988': patches / '988-net-airoha-add-source-aware-npu-transaction-transport.patch',
        '990': patches / '990-net-airoha-preserve-npu-lifecycle-transaction-identities.patch',
    }
    patch_bytes = {number: path.read_bytes() for number, path in patch_paths.items()}
    sources = {CORE: added_file(patch_bytes['990'].decode(), CORE)}
    for name in ABIS:
        sources[name] = added_file(patch_bytes['988'].decode(), name)
    extracted = output / 'source'
    extracted.mkdir(exist_ok=True)
    for name, data in sources.items():
        (extracted / name).write_bytes(data)
    command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-fno-omit-frame-pointer', '-I', str(extracted),
               str(tests / 'core_test.c'), '-o', str(output / 'core_test')]
    execute(command, output, 'build')
    environment = dict(os.environ)
    environment['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1'
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    result = execute([str(output / 'core_test')], output, 'core_test', environment)
    for number, path in patch_paths.items():
        if path.read_bytes() != patch_bytes[number]:
            raise RuntimeError(number + ' changed during testing; rerun against the completed patch')
    report = {
        'passed': True,
        'compiler': version.splitlines()[0],
        'sanitizers': ['address', 'undefined'],
        'sanitize_recover': False,
        'patch_sha256': {number: sha256(data) for number, data in patch_bytes.items()},
        'source_sha256': {name: sha256(data) for name, data in sources.items()},
        'test_sha256': {name: sha256((tests / name).read_bytes())
                        for name in ('verify.py', 'core_test.c')},
        'result': result,
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(result)
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
