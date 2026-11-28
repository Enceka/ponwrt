#!/usr/bin/env python3
"""Apply ZZ2 to a separate source copy and test real ER and owner functions."""
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
PATCH = '999-zz2-net-airoha-observe-authorized-pon-return-frames.patch'
TARGETS = ('airoha_eth_return.c', 'airoha_eth_return.h', 'airoha_npu_return.h')
DEPENDENCIES = ('npu_eth_return_abi.h', 'airoha_npu_flow_observe.h',
                'airoha_npu_flow_key.h', 'airoha_npu_auth_publish.h',
                'npu_auth_mailbox_abi.h')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def block(source, pattern, semicolon=False):
    matches = list(re.finditer(pattern, source, re.M))
    assert len(matches) == 1, pattern
    start = matches[0].start()
    position = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[position] == '{') - (source[position] == '}')
        position += 1
    return source[start:position + int(semicolon)] + '\n'


def run(command, output, label):
    result = subprocess.run(command, capture_output=True, text=True, timeout=60,
                            env={**os.environ, 'ASAN_OPTIONS': 'halt_on_error=1:abort_on_error=1',
                                 'UBSAN_OPTIONS': 'halt_on_error=1'})
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ':\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    source = args.source.resolve()
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(repo) or output.is_relative_to(source) or source.is_relative_to(output):
        parser.error('output must be new, outside ponwrt and separate from source')
    output.mkdir(parents=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    before = {name: digest(source / DRIVER / name) for name in TARGETS + DEPENDENCIES}
    driver = output / 'kernel' / DRIVER
    shutil.copytree(source / DRIVER, driver)
    patch = repo / 'target/linux/airoha/patches-6.18' / PATCH
    patch_hash = digest(patch)
    application = run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                       '-d', str(output / 'kernel'), '-p1', '-i', str(patch)], output, 'apply')
    assert not re.search(r'offset|fuzz|FAILED|reversed', application, re.I)
    assert re.findall(r'^\+\+\+ b/' + str(DRIVER) + r'/([^\n]+)$', patch.read_text(), re.M) == list(TARGETS)
    owner = (driver / 'airoha_npu_return.h').read_text()
    (output / 'owner.inc').write_text(
        block(owner, r'^struct airoha_npu_return \{', True) +
        ''.join(block(owner, r'^static (?:bool|void) ' + name + r'\([^;{]*\)\n\{') for name in
                ('airoha_npu_return_mapping', 'airoha_npu_return_binding', 'airoha_npu_return_observe')))
    assert '.observe = airoha_npu_return_observe,' in owner
    fixtures = tests.parent / 'eth_return'
    fixture = (fixtures / 'consumer_test.c').read_text()
    assert fixture.count('#include "airoha_eth_return.c"\n') == 1
    (output / 'consumer_fixture.inc').write_text(fixture.replace('#include "airoha_eth_return.c"\n', ''))
    stubs = output / 'stubs/linux'
    stubs.mkdir(parents=True)
    for name in ('types', 'device', 'netdevice', 'delay', 'dma-mapping', 'etherdevice', 'hrtimer', 'slab'):
        (stubs / (name + '.h')).write_text('#include "host_stubs.h"\n')
    (stubs / 'errno.h').write_text('#define EEXIST 17\n')
    (stubs / 'string.h').write_text('#include <string.h>\n')
    flags = ['clang', '-std=gnu11', '-D__KERNEL__', '-DTEST_OBSERVATION', '-Wall', '-Wextra',
             '-Werror', '-Wno-unused-function', '-O1', '-g', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-I', str(output / 'stubs'), '-I', str(fixtures),
             '-I', str(driver), '-I', str(output), str(tests / 'observe_test.c')]
    results = {}
    for name, extra in [('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])]:
        binary = output / name
        run(flags + extra + ['-o', str(binary)], output, name + '-build')
        results[name] = run([str(binary)], output, name)
    changes = [
        ('skip-callback', driver / 'airoha_eth_return.c', 'if (ring->ops->observe)', 'if (false)'),
        ('truncate-frame', driver / 'airoha_eth_return.c',
         'snapshot[ER_D_SERVICE], payload, size);', 'snapshot[ER_D_SERVICE], payload, 14);'),
        ('lose-service', output / 'owner.inc', 'service & 0xffffU);', '0);'),
        ('admit-diagnostic', output / 'owner.inc', 'READ_ONCE(owner->diag_lower) ||', 'false ||'),
        ('admit-closed-route', output / 'owner.inc', '!READ_ONCE(routes->pon_open) ||', 'false ||'),
        ('skip-binding-recheck', output / 'owner.inc',
         '!airoha_npu_return_binding(ctx, lower, config, service)', '(lower && false)'),
        ('admit-without-pon-full', output / 'owner.inc', '!READ_ONCE(eth->ct_pon_full) ||', 'false ||'),
        ('admit-diagnostic-config', output / 'owner.inc',
         'of_property_read_bool(eth->dev->of_node, "airoha,connac2-pon-er-diagnostic") ||', 'false ||'),
    ]
    mutations = {}
    for name, path, old, new in changes:
        original = path.read_text()
        assert original.count(old) == 1, name
        try:
            path.write_text(original.replace(old, new))
            binary = output / name
            run(flags + ['-o', str(binary)], output, name + '-build')
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
            (output / (name + '.log')).write_text(result.stdout + result.stderr)
            assert result.returncode and 'ER authorized production observation:' in result.stderr, name
            mutations[name] = result.returncode
        finally:
            path.write_text(original)
    assert before == {name: digest(source / DRIVER / name) for name in before}
    assert patch_hash == digest(patch)
    report = {'passed': True, 'results': results, 'mutations': mutations, 'patch_sha256': patch_hash,
              'source': str(source), 'baseline_sha256': before,
              'patched_sha256': {name: digest(driver / name) for name in TARGETS},
              'fixtures_sha256': {str(path): digest(path) for path in
                                 (fixtures / 'consumer_test.c', fixtures / 'host_stubs.h')},
              'tests_sha256': {path.name: digest(path) for path in tests.iterdir() if path.is_file()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
