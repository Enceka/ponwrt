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


def run(command, output, name, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def function(source, name):
    match = re.search(r'^(?:static )?[^;{}\n]+\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    assert match, name
    opening = source.index('{', match.start())
    depth = 1
    cursor = opening + 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[match.start():cursor] + '\n'


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
    assert not output.is_relative_to(repo)
    output.mkdir(parents=True, exist_ok=False)
    tree = output / 'kernel'
    relative = Path('drivers/net/ethernet/airoha')
    driver = tree / relative
    shutil.copytree(args.source / relative, driver)
    patch = repo / 'target/linux/airoha/patches-6.18/999-zi-net-airoha-start-rebuilt-npu-after-binding.patch'
    if not args.patched:
        applied = run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                       '-p1', '-i', str(patch)], output, 'apply', cwd=tree)
        assert 'offset' not in applied and 'fuzz' not in applied
    source = (driver / 'airoha_npu.c').read_text()
    probe = function(source, 'airoha_npu_probe')
    assert 'airoha_npu_boot(' not in probe and 'REG_CR_BOOT_TRIGGER' not in probe
    assert probe.index('!airoha_npu_resident_device(dev)') < probe.index('devm_platform_ioremap_resource')
    assert probe.index('instance->deferred_start = of_property_read_bool') < probe.index('airoha_npu_prepare_firmware(')
    assert probe.index('airoha_npu_prepare_firmware(') < probe.index('platform_set_drvdata(')
    assert re.search(r'err = airoha_npu_prepare_firmware\(npu, base, &res\);\s+if \(err\)\s+return err;', probe)
    for label, name in [('get', 'airoha_npu_get'), ('shutdown', 'airoha_npu_shutdown')]:
        (output / (label + '.inc')).write_text(function(source, name))
    shim = output / 'shim/linux/mutex.h'
    shim.parent.mkdir(parents=True)
    shim.write_text('''#ifndef TEST_MUTEX_H
#define TEST_MUTEX_H
struct mutex { int unused; };
#define lockdep_assert_held(pointer) ((void)(pointer))
#endif
''')
    build = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-function', '-pthread', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-I', str(driver), '-I', str(output),
             '-I', str(output / 'shim'), str(tests / 'start_test.c')]
    binary = output / 'startup'
    run(build + ['-o', str(binary)], output, 'build')
    result = run([str(binary)], output, 'startup', timeout=30)
    start = driver / 'airoha_npu_start.h'
    getter = output / 'get.inc'
    mutations = {
        'probe_starts_master': (start, 'instance->deferred_start ? 0 : airoha_npu_boot(npu)', 'airoha_npu_boot(npu)'),
        'repeat_boot': (start, 'if (instance->start_attempted)', 'if (false)'),
        'discard_start_error': (start, 'instance->start_error = err;', 'instance->start_error = 0;'),
        'ignore_quarantine': (start, 'instance->stopping || READ_ONCE(instance->transport_quarantined)', 'instance->stopping'),
        'allow_modules': (start, 'IS_BUILTIN(CONFIG_NET_AIROHA)', 'IS_ENABLED(CONFIG_NET_AIROHA)'),
        'allow_dynamic': (start, '!IS_ENABLED(CONFIG_OF_DYNAMIC)', 'true'),
        'ignore_ancestor': (start, 'of_node_check_flag(ancestor, OF_DYNAMIC)', 'false'),
        'allow_probing_eth': (getter, 'if (!device_is_bound(dev))', 'if (false)'),
        'leak_device': (getter, '\tplatform_device_put(pdev);', '\t(void)pdev;'),
        'leak_module': (getter, '\tmodule_put(THIS_MODULE);', '\t(void)THIS_MODULE;'),
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
            assert outcome.returncode and ('Assertion' in outcome.stderr or 'assertion' in outcome.stderr), name
            caught[name] = outcome.returncode
        finally:
            path.write_text(original)
    report = {'passed': True, 'patched_input': args.patched, 'result': result,
              'patch_sha256': digest(patch),
              'source_sha256': {name: digest(driver / name) for name in
                  ['airoha_npu.c', 'airoha_npu_start.h', 'airoha_npu_er_provider.h']},
              'tests_sha256': {path.name: digest(path) for path in tests.glob('*') if path.is_file()},
              'caught_mutations': caught}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
