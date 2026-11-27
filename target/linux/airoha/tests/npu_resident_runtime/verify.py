#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(source, name):
    match = re.search(r'^(?:static )?[^;{}\n]+\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    assert match, name
    opening = source.index('{', match.start())
    depth, cursor = 1, opening + 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[match.start():cursor] + '\n'


def run(command, output, name, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patched', action='store_true')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    output = args.output.resolve()
    source = args.source.resolve()
    if output.is_relative_to(repo) or output == source or source.is_relative_to(output):
        parser.error('output must be new, outside the repository and separate from source')
    output.mkdir(parents=True, exist_ok=False)
    relative = Path('drivers/net/ethernet/airoha')
    tree = output / 'kernel'
    driver = tree / relative
    shutil.copytree(source / relative, driver)
    patch = repo / 'target/linux/airoha/patches-6.18/999-zj-net-airoha-check-resident-npu-suppliers.patch'
    if not args.patched:
        applied = run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                       '-p1', '-i', str(patch)], output, 'apply', cwd=tree)
        assert 'offset' not in applied and 'fuzz' not in applied
    startup = (driver / 'airoha_npu_start.h').read_text()
    npu = (driver / 'airoha_npu.c').read_text()
    (output / 'fixed.inc').write_text(function(startup, 'airoha_npu_fixed_node') +
                                     function(startup, 'airoha_npu_resident_device'))
    (output / 'start.inc').write_text(function(startup, 'airoha_npu_start_bound'))
    (output / 'get.inc').write_text(function(npu, 'airoha_npu_get'))
    (output / 'put.inc').write_text(function(npu, 'airoha_npu_put'))
    assert '#include <linux/mfd/syscon.h>' in npu
    assert '#include "airoha_npu_resident.h"' in startup
    getter = (output / 'get.inc').read_text()
    assert getter.index('airoha_npu_resident_acquire(') < getter.index('airoha_npu_start_bound(')
    assert getter.count('airoha_npu_resident_release(&scope);') == 2
    build = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-function', '-pthread', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-I', str(driver), '-I', str(output),
             str(tests / 'runtime_test.c')]
    binary = output / 'resident-runtime'
    run(build + ['-o', str(binary)], output, 'build')
    result = json.loads(run([str(binary)], output, 'runtime', timeout=30))
    runtime = driver / 'airoha_npu_resident.h'
    fixed = output / 'fixed.inc'
    getter_path = output / 'get.inc'
    mutations = {
        'skip_runtime_gate': (getter_path, '\tif (resident) {', '\tif (false) {'),
        'allow_module_owner': (fixed, '!dev->driver->owner', 'true'),
        'allow_unbind_attrs': (fixed, 'dev->driver->suppress_bind_attrs', 'true'),
        'ignore_bound': (runtime, 'if (!device_is_bound(dev))', 'if (false)'),
        'ignore_actual_driver': (runtime, 'strcmp(dev->driver->name, name)', '(strcmp(dev->driver->name, name) && false)'),
        'ignore_reset_supplier': (runtime, '(supplier && supplier != args.np)', 'false'),
        'ignore_reset_cells': (runtime, 'args.args_count != 1', 'false'),
        'ignore_parent_identity': (runtime, 'node == parent->of_node', 'true'),
        'allow_unbound_parent': (runtime, 'if (!device_is_bound(parent))', 'if (false)'),
        'allow_other_parent_driver': (runtime, 'strcmp(parent->driver->name, "simple-pm-bus")', 'false'),
        'ignore_parent_owner': (runtime, 'parent->driver->owner ||', 'false ||'),
        'ignore_parent_override': (runtime, 'device_has_driver_override(parent) ||', 'false ||'),
        'ignore_parent_drvdata': (runtime, 'dev_get_drvdata(parent))', 'false)'),
        'ignore_parent_first_compatible': (runtime, 'of_property_match_string(parent->of_node, "compatible", "simple-bus") != 0', 'false'),
        'ignore_parent_match_data': (runtime, '!match->data ||', 'false ||'),
        'ignore_parent_match_compatible': (runtime, 'strcmp(match->compatible, "simple-bus")', 'false'),
        'ignore_syscon_driver': (runtime, 'chip->driver || chip->bus', 'false || chip->bus'),
        'ignore_extra_resources': (runtime, 'if (of_property_present(node, properties[index]))', 'if (of_property_present(node, properties[index]) && false)'),
        'ignore_registered': (runtime, 'device_is_registered(dev) ? 0 : -EPROBE_DEFER', '0'),
        'ignore_scu_link_failure': (runtime, 'if (!device_link_add(npu->dev, scu, DL_FLAG_AUTOREMOVE_SUPPLIER))',
                                    'if (!device_link_add(npu->dev, scu, DL_FLAG_AUTOREMOVE_SUPPLIER) && false)'),
        'leak_reference': (runtime, '\t\tput_device(scope->devices[index]);', '\t\t(void)scope->devices[index];'),
        'leak_lock': (runtime, 'if (scope->unlock[index])', 'if (scope->unlock[index] && false)'),
    }
    caught = {}
    for name, (path, before, after) in mutations.items():
        original = path.read_text()
        assert original.count(before) == 1, name
        try:
            path.write_text(original.replace(before, after))
            target = output / name
            run(build + ['-o', str(target)], output, name + '-build')
            outcome = subprocess.run([str(target)], text=True, capture_output=True, timeout=30)
            (output / (name + '.log')).write_text(outcome.stdout + outcome.stderr)
            assert outcome.returncode and re.search('assertion|Assertion', outcome.stderr), name
            caught[name] = outcome.returncode
        finally:
            path.write_text(original)
    report = {'passed': True, 'patched_input': args.patched, 'result': result,
              'patch_sha256': digest(patch), 'caught_mutations': caught,
              'source_sha256': {path.name: digest(path) for path in
                  [driver / 'airoha_npu.c', driver / 'airoha_npu_start.h', runtime]},
              'tests_sha256': {path.name: digest(path) for path in tests.iterdir() if path.is_file()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
