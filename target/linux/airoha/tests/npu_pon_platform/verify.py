#!/usr/bin/env python3
"""Test the actual ZZ1 PPE profile block, image make selection and inherited DTS."""

import argparse
from datetime import datetime
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks

DRIVER = Path('drivers/net/ethernet/airoha')
PATCH = '999-zz1-net-airoha-match-pon-full-platform-profile.patch'
BASE = 'an7581-fiberhome-hg5585f-ct'
PROFILE = 'airoha,connac2-pon-full'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dtb_nodes(data):
    magic, size, off_struct, off_strings = struct.unpack_from('>4I', data)
    assert magic == 0xd00dfeed and size == len(data)
    nodes, stack = {}, []
    offset = off_struct
    while True:
        token, = struct.unpack_from('>I', data, offset)
        offset += 4
        if token == 1:
            end = data.index(b'\0', offset)
            stack.append(data[offset:end].decode())
            nodes['/' + '/'.join(stack[1:])] = {}
            offset = (end + 4) & ~3
        elif token == 2:
            stack.pop()
        elif token == 3:
            length, nameoff = struct.unpack_from('>2I', data, offset)
            offset += 8
            name_start = off_strings + nameoff
            name = data[name_start:data.index(b'\0', name_start)].decode()
            nodes['/' + '/'.join(stack[1:])][name] = data[offset:offset + length]
            offset = (offset + length + 3) & ~3
        elif token == 9:
            assert not stack
            return nodes
        else:
            assert token == 4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=REPOSITORY.parent / 'pon-npu-diag-20261127/production-ingress/source')
    parser.add_argument('--output', type=Path, default=REPOSITORY.parent / 'pon-npu-diag-20261127/production-ingress' / datetime.now().strftime('platform-suite-%Y%m%d-%H%M%S'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--vm', default='ponwrt')
    parser.add_argument('--vm-kernel', default='/workdir/pon-npu-989')
    parser.add_argument('--skip-dts', action='store_true')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.is_relative_to(REPOSITORY) or output.is_relative_to(source) or source.is_relative_to(output):
        parser.error('output must be a new directory outside the repository and source')
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'tmp'
    temporary.mkdir()
    environment = dict(os.environ, TMPDIR=str(temporary), ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    commands, inputs = [], {}

    def read(path):
        data = path.read_bytes()
        inputs[path] = data
        return data

    def run(command, log, cwd=None, required=True):
        command = list(map(str, command))
        commands.append(command)
        result = subprocess.run(command, cwd=cwd, env=environment, text=True, capture_output=True, timeout=120)
        log.write_text(result.stdout + result.stderr)
        if required and result.returncode:
            raise RuntimeError(str(log) + '\n' + result.stdout + result.stderr)
        return result

    for path in HERE.iterdir():
        if path.is_file():
            read(path)
    read(HERE.parent / 'npu_ingress/source_binding.py')
    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    patch_data = binding.snapshot[PATCH]
    names = ('airoha_eth.h', 'airoha_eth.c', 'airoha_ppe.c', 'airoha_ct_cpu_fallback.h')
    sections = list(binding.sections(patch_data, names))
    assert len(sections) == len(names)
    staged = output / 'patched-source'
    shutil.copytree(source, staged)
    for name in names:
        read(source / DRIVER / name)
    before = (staged / DRIVER / 'airoha_ppe.c').read_text()
    already_applied = 'ram_lab + full + pon != 1' in before
    patch_file = output / PATCH
    patch_file.write_bytes(patch_data)
    if already_applied:
        result = run(['patch', '--batch', '--fuzz=0', '-R', '-p1', '-i', patch_file], output / 'reverse.log', cwd=staged)
        assert not re.search(r'fuzz|offset|FAILED|reversed', result.stdout + result.stderr, re.I)
    for name, added, section in sections:
        assert not added
        exact_hunks((staged / DRIVER / name).read_bytes(), section)
    gnu_command = ['patch', '--dry-run', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch_file, '-d', staged]
    result = run(['orb', '-m', args.vm, 'bash', '-lc', shlex.join(map(str, gnu_command))], output / 'gnu-patch-dry-run.log')
    assert not re.search(r'fuzz|offset|FAILED|reversed', result.stdout + result.stderr, re.I)
    result = run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch_file], output / 'apply.log', cwd=staged)
    assert not re.search(r'fuzz|offset|FAILED|reversed', result.stdout + result.stderr, re.I)
    if already_applied:
        for name in names:
            assert (staged / DRIVER / name).read_bytes() == inputs[source / DRIVER / name]
    text = (staged / DRIVER / 'airoha_ppe.c').read_text()
    init = text[text.index('int airoha_ppe_init('):]
    start = init.index('\n\t{\n\t\tstruct device_node *np = of_parse_phandle(') + 1
    end = init.index('\n\tppe_num_entries =', start)
    profile = init[start:end]
    assert profile.count('{') == profile.count('}')
    compiler = shlex.split(args.cc)
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    version = run(compiler + ['--version'], output / 'compiler.log').stdout

    def profile_run(label, block):
        directory = output / label
        directory.mkdir()
        (directory / 'profile.inc').write_text(block)
        binary = directory / 'profile-test'
        run(compiler + flags + ['-I', directory, HERE / 'profile_test.c', '-o', binary], directory / 'build.log')
        return run([binary], directory / 'run.log', required=False)

    result = profile_run('baseline', profile)
    assert not result.returncode, result.stdout + result.stderr
    baseline = json.loads(result.stdout)
    print('PASS profile ' + result.stdout.strip(), flush=True)
    mutants = []
    edits = (
        ('ignore-pon-profile', 'ram_lab || full || pon || eth_ram || eth_full || eth_pon', 'ram_lab || full || eth_ram || eth_full'),
        ('allow-multiple', 'ram_lab + full + pon != 1', 'ram_lab + full + pon == 0'),
        ('ignore-requested', '!airoha_ppe_ct_requested(eth)', '(airoha_ppe_ct_requested(eth) && false)'),
        ('ignore-ram-mismatch', 'ram_lab != eth_ram ||', 'false ||'),
        ('ignore-full-mismatch', 'full != eth_full ||', 'false ||'),
        ('ignore-pon-mismatch', 'pon != eth_pon', 'false'),
        ('allocation-error-success', 'return -ENOMEM;', 'return 0;'),
        ('native-flag-missing', 'ppe->ct_native_pairs = true;', 'ppe->ct_native_pairs = false;'),
        ('node-reference-leak', 'of_node_put(np);', 'if (false) of_node_put(np);'),
    )
    for name, old, new in edits:
        assert profile.count(old) == 1
        result = profile_run(name, profile.replace(old, new, 1))
        assert result.returncode == 1 and 'CHECK failed' in result.stderr and not re.search(r'Sanitizer|runtime error:', result.stderr), (name, result.stderr)
        mutants.append({'name': name, 'assertion': result.stderr.strip()})
    image = REPOSITORY / 'target/linux/airoha/image/an7581.mk'
    read(image)
    harness = output / 'image-test.mk'
    harness.write_text('include ' + str(image) + '\n$(eval $(call Device/fiberhome_hg5585f-ct))\n'
                       '$(info DTS=$(DEVICE_DTS))\n$(info PACKAGES=$(DEVICE_PACKAGES))\n'
                       '$(info INITRAMFS=$(KERNEL_INITRAMFS))\n$(info SYSUPGRADE=$(IMAGE/sysupgrade.itb))\n'
                       '$(info IMAGES=$(IMAGES))\n.PHONY: probe\nprobe:\n\t@:\n')
    make_dir = output / 'make'
    make_dir.mkdir()
    make_results = []
    for pon, rebuilt, full, ram, stock, wed in itertools.product(('n', 'm', 'y'), ('n', 'm', 'y'), ('n', 'm', 'y'), (0, 1), ('n', 'y'), ('n', 'y')):
        config = dict(zip(('pon', 'rebuilt', 'full', 'ram', 'stock', 'wed'), (pon, rebuilt, full, ram, stock, wed)))
        assignments = {
            'CONFIG_PACKAGE_hg5585f-ct-npu-pon-full-firmware': pon,
            'CONFIG_PACKAGE_hg5585f-ct-npu-rebuilt-firmware': rebuilt,
            'CONFIG_PACKAGE_hg5585f-ct-npu-full-test-firmware': full,
            'CONFIG_PACKAGE_hg5585f-ct-npu-firmware': stock,
            'CONFIG_PACKAGE_kmod-mt7916-ct-wed-prepare': wed,
            'HG5585F_CT_RAM_TRIAL': ram,
        }
        result = run(['make', '--no-print-directory', '-f', harness, 'probe'] + [key + '=' + str(value) for key, value in assignments.items()],
                     make_dir / (str(len(make_results)) + '.log'), required=False)
        conflict = (full == 'y' and ram) or (pon == 'y' and (ram or rebuilt in ('y', 'm') or full in ('y', 'm')))
        assert bool(result.returncode) == bool(conflict), (config, result.stdout, result.stderr)
        if conflict:
            assert re.search(r'mutually exclusive|conflicts with rebuilt/full-test', result.stderr)
        else:
            values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
            expected = BASE + ('-connac2' if stock == 'y' else '') + ('-wed' if wed == 'y' and not ram else '') + ('-ram' if ram else '')
            if full == 'y':
                expected = BASE + '-connac2-wed-full-test'
            if pon == 'y':
                expected = BASE + '-connac2-wed-pon-full'
            assert values['DTS'] == expected, (config, values)
            packages = values['PACKAGES'].split()
            assert ('hg5585f-ct-npu-pon-full-firmware' in packages) == (pon == 'y')
            assert ('hg5585f-ct-npu-full-test-firmware' in packages) == (full == 'y')
            assert ('hg5585f-ct-npu-firmware' in packages) == (stock == 'y')
            assert 'image-' + expected + '.dtb' in values['INITRAMFS']
            assert 'image-' + expected + '.dtb' in values['SYSUPGRADE']
            assert values['IMAGES'] == ('' if ram else 'sysupgrade.itb')
        make_results.append({'config': config, 'conflict': bool(conflict), 'exit_code': result.returncode})
    print('PASS make matrix: ' + str(len(make_results)) + ' configurations', flush=True)
    overlay = REPOSITORY / 'target/linux/airoha/hg5585f-ct/prepare-overlay.sh'
    overlay_text = read(overlay).decode()
    run(['bash', '-n', overlay], output / 'overlay-syntax.log')
    for marker in ('--pon-full', PATCH, BASE + '-connac2-wed-pon-full.dts', 'CONFIG_PACKAGE_hg5585f-ct-npu-pon-full-firmware=y'):
        assert marker in overlay_text
    dts_report = {'skipped': args.skip_dts}
    if not args.skip_dts:
        dts_dir = REPOSITORY / 'target/linux/airoha/dts'
        for path in dts_dir.iterdir():
            if path.suffix in ('.dts', '.dtsi'):
                read(path)
        dts = dts_dir / (BASE + '-connac2-wed-pon-full.dts')
        preprocessed, blob = output / 'pon-full.dts', output / 'pon-full.dtb'
        cpp = ['cpp', '-nostdinc', '-undef', '-D__DTS__', '-x', 'assembler-with-cpp', '-I', dts_dir,
               '-I', args.vm_kernel + '/include', dts]
        result = run(['orb', '-m', args.vm, 'bash', '-lc', shlex.join(map(str, cpp))], output / 'cpp.log')
        preprocessed.write_text(result.stdout)
        includes = sorted(set(re.findall(r'^#\s+\d+\s+"([^"]+)"', result.stdout, re.M)))
        includes = [path for path in includes if path.startswith('/')]
        hash_code = 'import hashlib,json,sys;print(json.dumps({p:hashlib.sha256(open(p,"rb").read()).hexdigest() for p in sys.argv[1:]}))'
        hash_command = ['orb', '-m', args.vm, 'python3', '-c', hash_code, *includes]
        include_hashes = json.loads(run(hash_command, output / 'dts-inputs-before.json').stdout)
        dtc = ['dtc', '-@', '-I', 'dts', '-O', 'dtb', '-o', blob, preprocessed]
        run(['orb', '-m', args.vm, 'bash', '-lc', shlex.join(map(str, dtc))], output / 'dtc.log')
        assert json.loads(run(hash_command, output / 'dts-inputs-after.json').stdout) == include_hashes
        nodes = dtb_nodes(blob.read_bytes())
        symbols = nodes['/__symbols__']
        eth_path, npu_path = [symbols[label].rstrip(b'\0').decode() for label in ('eth', 'npu')]
        for node in (nodes[eth_path], nodes[npu_path]):
            assert node[PROFILE] == b''
            assert not any(name in node for name in ('airoha,connac2-ordinary-full-test', 'airoha,connac2-ram-native-pairs', 'airoha,connac2-rebuilt-ram-lab'))
        assert nodes['/']['variant'] == b'pon-full\0'
        assert b'fiberhome,hg5585f-ct\0' in nodes['/']['compatible']
        assert nodes[eth_path]['airoha,connac2-host-ppe'] == b''
        assert nodes[eth_path]['airoha,npu'] == nodes[npu_path]['phandle']
        assert symbols['ct_wed_slot1']
        dts_report = {'passed': True, 'eth': eth_path, 'npu': npu_path, 'inputs_sha256': include_hashes,
                      'dtb_sha256': digest(blob.read_bytes()), 'preprocessed_sha256': digest(preprocessed.read_bytes())}
        print('PASS compiled DTS inherited PON/WED/host-PPE profile', flush=True)
    for path, data in inputs.items():
        assert path.read_bytes() == data, 'input changed during run: ' + str(path)
    assert (binding.patches / PATCH).read_bytes() == patch_data
    report = {'passed': True, 'profile': baseline, 'mutants': mutants, 'make': make_results, 'dts': dts_report,
              'source_binding': {'patch': PATCH, 'patch_sha256': digest(patch_data), 'already_applied': already_applied,
                                 'exact_hunks': True, 'gnu_patch_dry_run': True, 'fuzz': 0, 'offset': 0,
                                 'patched_sha256': {name: digest((staged / DRIVER / name).read_bytes()) for name in names},
                                 'profile_block_sha256': digest(profile.encode())},
              'overlay': {'syntax': True, 'pon_full_selection_markers': True, 'executed': False},
              'inputs_sha256': {str(path): digest(data) for path, data in inputs.items()},
              'sanitizers': ['address', 'undefined'], 'compiler': version, 'commands': commands}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS report: ' + str(output / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
