#!/usr/bin/env python3
"""Extract the real Ethernet Return consumer and run deterministic host tests."""

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


def added_file(patch, relative):
    marker = '--- /dev/null\n+++ b/' + relative + '\n'
    if patch.count(marker) != 1:
        raise ValueError('expected one complete new file: ' + relative)
    lines = patch.split(marker, 1)[1].splitlines(keepends=True)
    match = re.fullmatch(r'@@ -0,0 \+1,(\d+) @@\n', lines[0])
    if not match:
        raise ValueError('expected a complete addition hunk: ' + relative)
    count = int(match.group(1))
    body = lines[1:count + 1]
    if len(body) != count or any(not line.startswith('+') for line in body):
        raise ValueError('invalid addition hunk: ' + relative)
    if len(lines) > count + 1 and lines[count + 1].startswith(('+', '@@')):
        raise ValueError('addition hunk length mismatch: ' + relative)
    return ''.join(line[1:] for line in body)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, output, label, env=None):
    result = subprocess.run(command, text=True, capture_output=True, env=env, cwd=output)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ' failed:\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    patch_dir = repo / 'target/linux/airoha/patches-6.18'
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=tests / 'out')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--firmware', type=Path,
                        default=repo.parents[1] / 'an7581-npu-firmware',
                        help='Firmware tree whose include/npu_eth_return_abi.h is checked')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError('compiler unavailable: ' + args.cc)
    version = run([compiler, '--version'], output, 'compiler')
    if 'clang' not in version.lower():
        raise RuntimeError('this runner requires clang')
    consumer_patch = patch_dir / '989-net-airoha-add-source-aware-ethernet-return-consumers.patch'
    transport_patch = patch_dir / '988-net-airoha-add-source-aware-npu-transaction-transport.patch'
    consumer_bytes = consumer_patch.read_bytes()
    transport_bytes = transport_patch.read_bytes()
    consumer = consumer_bytes.decode()
    transport = transport_bytes.decode()
    extracted = output / 'source'
    extracted.mkdir(exist_ok=True)
    sources = {}
    for name in ('airoha_eth_return.c', 'airoha_eth_return.h'):
        sources[name] = added_file(consumer, DRIVER + name).encode()
    abi_name = 'npu_eth_return_abi.h'
    firmware_abi = (args.firmware / 'include' / abi_name).read_bytes()
    abi_marker = '--- /dev/null\n+++ b/' + DRIVER + abi_name + '\n'
    if abi_marker in transport:
        sources[abi_name] = added_file(transport, DRIVER + abi_name).encode()
        if sources[abi_name] != firmware_abi:
            raise RuntimeError('988 Ethernet Return ABI differs from firmware')
        abi_origin = str(transport_patch)
    else:
        sources[abi_name] = firmware_abi
        abi_origin = str(args.firmware / 'include' / abi_name)
    for name, contents in sources.items():
        (extracted / name).write_bytes(contents)
    linux = output / 'stubs/linux'
    linux.mkdir(parents=True, exist_ok=True)
    for name in ('types', 'device', 'netdevice', 'delay', 'dma-mapping',
                 'etherdevice', 'hrtimer', 'slab'):
        (linux / (name + '.h')).write_text('#include "host_stubs.h"\n')
    build = [compiler, '-std=gnu11', '-D__KERNEL__', '-Wall', '-Wextra', '-Werror',
             '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-fno-omit-frame-pointer', '-I', str(output / 'stubs'),
             '-I', str(tests), '-I', str(extracted), str(tests / 'consumer_test.c')]
    environment = dict(os.environ)
    environment['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1'
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    modes = {}
    for name, flags in (('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])):
        binary = output / name
        run(build + flags + ['-o', str(binary)], output, name + '-build')
        modes[name] = run([str(binary)], output, name, env=environment)
        print(name + ': ' + modes[name])
    if consumer_patch.read_bytes() != consumer_bytes or transport_patch.read_bytes() != transport_bytes:
        raise RuntimeError('988/989 changed during this run; rerun against the completed patches')
    report = {
        'passed': True,
        'compiler': version.splitlines()[0],
        'sanitizers': ['address', 'undefined'],
        'sanitize_recover': False,
        'patch_sha256': {'989': digest(consumer_bytes), '988': digest(transport_bytes)},
        'source_sha256': {name: digest(data) for name, data in sources.items()},
        'test_sha256': {name: digest((tests / name).read_bytes()) for name in
                        ('verify.py', 'host_stubs.h', 'consumer_test.c')},
        'abi_origin': abi_origin,
        'firmware_abi_match': True,
        'modes': modes,
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('report: ' + str(output / 'report.json'))


if __name__ == '__main__':
    main()
