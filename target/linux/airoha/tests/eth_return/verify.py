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
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks


DRIVER = Path('drivers/net/ethernet/airoha')
FILES = ('airoha_eth_return.c', 'airoha_eth_return.h', 'npu_eth_return_abi.h')


def selected_patches(binding, snapshot):
    return {name: data for name, data in snapshot.items()
            if list(binding.sections(data, FILES))}


def reconstruct(binding, output):
    sources = {}
    chains = {name: [] for name in FILES}
    applied = output / 'applied-patches'
    applied.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='patch-replay-', dir=output) as temporary:
        tree = Path(temporary)
        driver = tree / DRIVER
        driver.mkdir(parents=True)
        for patch_name, data in selected_patches(binding, binding.snapshot).items():
            sections = list(binding.sections(data, FILES))
            for name, added, section in sections:
                if added == (name in sources):
                    raise ValueError('missing or duplicate creation: ' + name)
                exact_hunks(sources.get(name, b''), section)
            patch_file = applied / patch_name
            patch_file.write_text(''.join(section for name, added, section in sections))
            result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0',
                                     '--no-backup-if-mismatch', '-p1', '-i', str(patch_file)],
                                    cwd=tree, capture_output=True, text=True, timeout=30)
            log = result.stdout + result.stderr
            (applied / (patch_name + '.log')).write_text(log)
            if result.returncode or re.search(r'fuzz|offset|FAILED|reversed', log, re.I):
                raise ValueError('patch does not apply exactly: ' + patch_name + '\n' + log)
            for name, added, section in sections:
                sources[name] = (driver / name).read_bytes()
                chains[name].append(patch_name)
    for name in FILES:
        if not chains[name]:
            raise ValueError('no production patch creates ' + name)
    return sources, chains


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
    parser.add_argument('--source', type=Path,
                        help='Patched kernel tree whose three ER files must match the production patch chain')
    parser.add_argument('--firmware', type=Path,
                        default=repo.parents[1] / 'an7581-npu-firmware',
                        help='Firmware tree whose include/npu_eth_return_abi.h is checked')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    report_path.unlink(missing_ok=True)
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError('compiler unavailable: ' + args.cc)
    version = run([compiler, '--version'], output, 'compiler')
    if 'clang' not in version.lower():
        raise RuntimeError('this runner requires clang')
    binding_module = tests.parent / 'npu_ingress/source_binding.py'
    binding_bytes = binding_module.read_bytes()
    binding = SourceBinding(patch_dir, output)
    sources, chains = reconstruct(binding, output)
    source = args.source.resolve() if args.source else None
    source_bytes = {}
    if source:
        source_bytes = {name: (source / DRIVER / name).read_bytes() for name in FILES}
        for name in FILES:
            if source_bytes[name] != sources[name]:
                raise RuntimeError('input kernel differs from production patch chain: ' + name)
    extracted = output / 'source'
    extracted.mkdir(exist_ok=True)
    abi_name = 'npu_eth_return_abi.h'
    firmware_abi_path = args.firmware.resolve() / 'include' / abi_name
    firmware_abi = firmware_abi_path.read_bytes()
    if sources[abi_name] != firmware_abi:
        raise RuntimeError('production patch-chain ER ABI differs from firmware')
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
    if b'airoha_er_enable_observation' in sources['airoha_eth_return.c']:
        build.append('-DTEST_OBSERVATION')
    environment['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1'
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    modes = {}
    for name, flags in (('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])):
        binary = output / name
        run(build + flags + ['-o', str(binary)], output, name + '-build')
        modes[name] = run([str(binary)], output, name, env=environment)
        print(name + ': ' + modes[name])
    used_patches = selected_patches(binding, binding.snapshot)
    current_patches = selected_patches(binding, binding.read_patches())
    if list(current_patches.items()) != list(used_patches.items()):
        raise RuntimeError('production ER patch chain changed during this run; rerun')
    for name, data in sources.items():
        if (extracted / name).read_bytes() != data:
            raise RuntimeError('extracted source changed during this run: ' + name)
        if source and (source / DRIVER / name).read_bytes() != source_bytes[name]:
            raise RuntimeError('input kernel changed during this run: ' + name)
    if firmware_abi_path.read_bytes() != firmware_abi or binding_module.read_bytes() != binding_bytes:
        raise RuntimeError('firmware ABI or source-binding helper changed during this run; rerun')
    report = {
        'passed': True,
        'compiler': version.splitlines()[0],
        'sanitizers': ['address', 'undefined'],
        'sanitize_recover': False,
        'patch_directory': str(patch_dir),
        'patch_order': list(used_patches),
        'patch_sha256': {name: digest(data) for name, data in used_patches.items()},
        'source_patch_chains': chains,
        'source_sha256': {name: digest(data) for name, data in sources.items()},
        'input_source': str(source) if source else None,
        'input_source_sha256': {name: digest(data) for name, data in source_bytes.items()},
        'input_source_match': True if source else None,
        'source_binding': {'path': str(binding_module), 'sha256': digest(binding_bytes)},
        'test_sha256': {name: digest((tests / name).read_bytes()) for name in
                        ('verify.py', 'host_stubs.h', 'consumer_test.c')},
        'abi_origin': [str(patch_dir / name) for name in chains[abi_name]],
        'firmware_abi_origin': str(firmware_abi_path),
        'firmware_abi_sha256': digest(firmware_abi),
        'firmware_abi_match': True,
        'modes': modes,
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
