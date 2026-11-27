#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request


SOURCE_URL = 'https://raw.githubusercontent.com/torvalds/linux/v6.18/drivers/clk/clk-en7523.c'
SOURCE_SHA256 = '37c592b22e4a2ea1f6fc0f1c614ddc252cb5775a973f431c7e0c055535955940'
DRIVER = 'drivers/clk/clk-en7523.c'
FIX = '609-05-clk-en7523-fix-reset-values-and-regmap-errors.patch'
FUNCTIONS = ('en7523_reset_update', 'en7523_reset_assert',
             'en7523_reset_deassert', 'en7523_reset_status')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def extract(source, name):
    matches = list(re.finditer(r'^static int ' + name + r'\([^;{}]*\)\n\{', source, re.M))
    if len(matches) != 1:
        raise ValueError('expected one production function: ' + name)
    start = matches[0].start()
    opening = matches[0].end() - 1
    depth = 0
    for end in range(opening, len(source)):
        depth += (source[end] == '{') - (source[end] == '}')
        if not depth:
            return source[start:end + 1] + '\n'
    raise ValueError('unterminated function: ' + name)


def execute(command, output, label, cwd=None, expected_failure=False):
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    result = subprocess.run(command, cwd=cwd or output, env=environment,
                            text=True, capture_output=True)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if expected_failure:
        if not result.returncode or 'FAIL line ' not in result.stderr:
            raise RuntimeError('mutation escaped runtime checks: ' + label)
    elif result.returncode:
        raise RuntimeError(label + ':\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('unexpected mutation target: ' + before)
    return source.replace(before, after, 1)


def main():
    tests = Path(__file__).resolve().parent
    patches = tests.parents[1] / 'patches-6.18'
    parser = argparse.ArgumentParser(description='Test extracted EN7581 reset provider functions')
    parser.add_argument('--base-source', type=Path, help='Unpatched Linux v6.18 clk-en7523.c; SHA checked')
    parser.add_argument('--output', type=Path, help='Artifacts; default is a new temporary directory')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='airoha-reset-provider-'))
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    report_path.unlink(missing_ok=True)
    if args.base_source:
        baseline = args.base_source.read_bytes()
    else:
        with urllib.request.urlopen(SOURCE_URL, timeout=30) as response:
            baseline = response.read()
    if digest(baseline) != SOURCE_SHA256:
        raise ValueError('unexpected upstream clk-en7523.c SHA-256')
    (output / 'upstream-clk-en7523.c').write_bytes(baseline)
    tree = output / 'kernel'
    source_path = tree / DRIVER
    source_path.parent.mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(baseline)
    patch_inputs = {}
    before_fix = None
    for patch in sorted(patches.glob('*.patch')):
        data = patch.read_bytes()
        if ('\n+++ b/' + DRIVER + '\n').encode() not in data:
            continue
        if re.findall(rb'^\+\+\+ b/(.+)$', data, re.M) != [DRIVER.encode()]:
            raise ValueError('unexpected extra file in clock patch: ' + patch.name)
        patch_inputs[patch] = data
        if patch.name == FIX:
            before_fix = source_path.read_text()
        applied = execute(['patch', '--batch', '--forward', '--fuzz=0',
                           '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                          output, patch.name, cwd=tree)
        if re.search(r'fuzz|FAILED|reversed', applied, re.I):
            raise RuntimeError('patch context mismatch: ' + patch.name)
        if patch.name == FIX and 'offset' in applied.lower():
            raise RuntimeError('reset fix must apply without offsets')
    if before_fix is None:
        raise ValueError('missing reset provider fix')
    source = source_path.read_text()
    functions = '\n'.join(extract(source, name) for name in FUNCTIONS)
    types = []
    for name in ('RST_NR_PER_BANK', 'REG_NP_SCU_PCIC', 'REG_RST_CTRL1', 'REG_RST_CTRL2'):
        match = re.search(r'^#define\s+' + name + r'\s+[^\n]+$', source, re.M)
        if not match:
            raise ValueError('missing production constant: ' + name)
        types.append(match.group())
    for declaration in ('struct en_rst_data', 'static const u16 en7581_rst_ofs[]'):
        match = re.search('^' + re.escape(declaration) + r'[^\n]*\{\n.*?^\};', source, re.M | re.S)
        if not match:
            raise ValueError('missing production declaration: ' + declaration)
        types.append(match.group())
    (output / 'reset_types.inc').write_text('\n'.join(types) + '\n')
    extracted = output / 'reset_functions.inc'
    version = execute([args.cc, '--version'], output, 'compiler')
    if 'clang' not in version.lower():
        raise ValueError('clang is required for automatic variable initialization modes')
    compile_command = [args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
                       '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                       '-fno-omit-frame-pointer', '-I', str(output), str(tests / 'reset_test.c'),
                       '-o', str(output / 'reset_test')]
    results = {}
    for mode in ('zero', 'pattern'):
        extracted.write_text(functions)
        execute(compile_command + ['-ftrivial-auto-var-init=' + mode], output, 'build-' + mode)
        results[mode] = execute([str(output / 'reset_test')], output, 'test-' + mode)
    if functions.count('\tu32 val;\n') != 2:
        raise ValueError('expected both production value declarations')
    seeded = functions.replace('\tu32 val;\n', '\tu32 val = initial_value;\n')
    extracted.write_text(seeded)
    execute(compile_command + ['-DSEEDED_LOCALS'], output, 'build-seeded')
    results['seeded'] = execute([str(output / 'reset_test')], output, 'test-seeded')
    original = '\n'.join(extract(before_fix, name) for name in FUNCTIONS)
    original = original.replace('\tu32 val;\n', '\tu32 val = initial_value;\n')
    mutations = {
        'original-provider': original,
        'or-stale-value': seeded.replace('\t\tval = assert ?', '\t\tval |= assert ?'),
        'ignore-update-error': replace_once(seeded,
            '\treturn regmap_update_bits(rst_data->map, addr, BIT(id % RST_NR_PER_BANK),\n\t\t\t\t  val);',
            '\tregmap_update_bits(rst_data->map, addr, BIT(id % RST_NR_PER_BANK),\n\t\t\t\t  val);\n\treturn 0;'),
        'ignore-read-error': replace_once(seeded, '\tif (err)\n\t\treturn err;\n', '\t(void)err;\n'),
        'wrong-pcic-polarity': replace_once(seeded, 'val = assert ? 0 : BIT(id % RST_NR_PER_BANK);',
            'val = assert ? BIT(id % RST_NR_PER_BANK) : 0;'),
        'overwrite-other-bits': replace_once(seeded,
            'regmap_update_bits(rst_data->map, addr, BIT(id % RST_NR_PER_BANK),',
            'regmap_update_bits(rst_data->map, addr, UINT32_MAX,'),
        'wrong-status-polarity': replace_once(seeded,
            'return inverted ? !val : !!val;', 'return inverted ? !!val : !val;'),
    }
    for name, changed in mutations.items():
        if changed == seeded:
            raise ValueError('unchanged mutation: ' + name)
        extracted.write_text(changed)
        execute(compile_command + ['-DSEEDED_LOCALS'], output, 'build-' + name)
        execute([str(output / 'reset_test')], output, 'test-' + name, expected_failure=True)
    extracted.write_text(functions)
    execute(compile_command + ['-ftrivial-auto-var-init=pattern'], output, 'build-final')
    results['final'] = execute([str(output / 'reset_test')], output, 'test-final')
    for patch, data in patch_inputs.items():
        if patch.read_bytes() != data:
            raise RuntimeError('clock patch changed during testing: ' + patch.name)
    report = {
        'passed': True, 'source_url': SOURCE_URL, 'source_sha256': SOURCE_SHA256,
        'compiler': version.splitlines()[0], 'sanitizers': ['address', 'undefined'],
        'patches_sha256': {patch.name: digest(data) for patch, data in patch_inputs.items()},
        'patched_source_sha256': digest(source.encode()),
        'extracted_functions_sha256': {name: digest(extract(source, name).encode()) for name in FUNCTIONS},
        'test_sha256': {name: digest((tests / name).read_bytes()) for name in ('verify.py', 'reset_test.c')},
        'results': results, 'runtime_mutations_caught': list(mutations),
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    for name, result in results.items():
        print(name + ': ' + result)
    print('runtime mutations caught: ' + str(len(mutations)))
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
