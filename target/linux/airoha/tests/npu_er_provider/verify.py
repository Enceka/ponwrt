#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import resource
import shutil
import subprocess


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, output, name, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patched', action='store_true')
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    patch = repo / 'target/linux/airoha/patches-6.18/999-zg-net-airoha-track-er-provider-exposure.patch'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    tree = output / 'kernel'
    relative = Path('drivers/net/ethernet/airoha')
    driver = tree / relative
    shutil.copytree(args.source / relative, driver)
    if not args.patched:
        applied = run(['patch', '--batch', '--forward', '--fuzz=0',
                       '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                      output, 'apply', cwd=tree)
        assert 'fuzz' not in applied and 'offset' not in applied, applied
    shim = output / 'shim/linux/mutex.h'
    shim.parent.mkdir(parents=True)
    shim.write_text('''#ifndef TEST_MUTEX_H
#define TEST_MUTEX_H
#include <pthread.h>
#include <stdatomic.h>
struct mutex { pthread_mutex_t native; atomic_int held; };
static inline void mutex_init(struct mutex *lock)
{ assert(!pthread_mutex_init(&lock->native, NULL)); atomic_init(&lock->held, 0); }
static inline void mutex_lock(struct mutex *lock)
{ assert(!pthread_mutex_lock(&lock->native)); assert(!atomic_exchange(&lock->held, 1)); }
static inline void mutex_unlock(struct mutex *lock)
{ assert(atomic_exchange(&lock->held, 0) == 1); assert(!pthread_mutex_unlock(&lock->native)); }
#define lockdep_assert_held(lock) assert(atomic_load(&(lock)->held) == 1)
#endif
''')
    source_files = [driver / name for name in ['airoha_npu.c', 'airoha_npu_transaction.inc',
                    'airoha_npu_er_provider.h', 'npu_eth_return_abi.h']]
    hashes = {str(path.relative_to(tree)): digest(path) for path in source_files}
    build = [args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
             '-pthread', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-I', str(output / 'shim'), '-I', str(driver), str(tests / 'provider_test.c')]
    results = {}
    for mode, flags in [('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])]:
        binary = output / mode
        run(build + flags + ['-o', str(binary)], output, mode + '-build')
        results[mode] = run([str(binary)], output, mode)
    legacy_path = tests.parent / 'npu_transaction_transport/transport_test.c'
    legacy = legacy_path.read_text()
    before = 'return airoha_npu_er_command(instance,'
    assert legacy.count(before) == 1
    legacy = legacy.replace(before, 'return airoha_npu_er_exchange(instance,')
    legacy = legacy.replace('#include "airoha_npu_transaction.inc"',
                            '#include "airoha_npu_er_provider.h"\n'
                            '#include "airoha_npu_transaction.inc"')
    legacy = ('#include <stddef.h>\n#define container_of(pointer, type, member) '
              '((type *)((char *)(pointer) - offsetof(type, member)))\n') + legacy
    legacy_source = output / 'transport_regression.c'
    legacy_source.write_text(legacy)
    for mode, flags in [('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])]:
        name = 'transport-' + mode
        binary = output / name
        run(build[:-1] + [str(legacy_source)] + flags + ['-o', str(binary)],
            output, name + '-build')
        results[name] = run([str(binary)], output, name)
    provider = driver / 'airoha_npu_er_provider.h'
    transport = driver / 'airoha_npu_transaction.inc'
    mutations = {
        'identity': (provider, 'memcmp(&source->config, &config, sizeof(config))', '0'),
        'alias_window': (provider, '\tbase = config.dma & (ER_WINDOW - 1);', '\tbase = config.dma;'),
        'stop_required': (provider, 'source->exposed && !source->stopped', 'false'),
        'epoch': (provider, 'config.epoch <= source->config.epoch', 'false'),
        'exposure_before_send': (provider, 'source->exposed = true;', 'source->exposed = false;'),
        'error_retention': (transport, 'if (!err)\n\t\t\tairoha_npu_er_complete',
                            'if (true)\n\t\t\tairoha_npu_er_complete'),
        'request_idle': (transport, 'le32_to_cpu(reply[10]) != ER_IDLE || reply[12]', 'reply[12]'),
        'fault_free': (transport, 'le32_to_cpu(reply[10]) != ER_IDLE || reply[12]',
                       'le32_to_cpu(reply[10]) != ER_IDLE'),
    }
    caught = {}
    for name, (path, before, after) in mutations.items():
        original = path.read_text()
        assert original.count(before) == 1, name
        try:
            path.write_text(original.replace(before, after))
            binary = output / name
            run(build + ['-o', str(binary)], output, name + '-build')
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            (output / (name + '.log')).write_text(result.stdout + result.stderr)
            assert result.returncode, 'missed mutation: ' + name
            caught[name] = result.returncode
        finally:
            path.write_text(original)
    report = {'passed': True, 'patched_input': args.patched,
              'patch_sha256': digest(patch), 'source_sha256': hashes,
              'transport_regression_sha256': digest(legacy_path),
              'tests_sha256': {path.name: digest(path) for path in tests.glob('*') if path.is_file()},
              'modes': results, 'caught_mutations': caught}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
