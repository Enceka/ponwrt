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
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def extract_function(source, name):
    match = re.search(r'^static [^;{}]*\b' + re.escape(name) + r'\([^;{}]*\)\n\{',
                      source, re.MULTILINE)
    assert match, name
    start = match.start()
    opening = source.index('{', start)
    depth = 1
    cursor = opening + 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[start:cursor] + '\n'


def extract(driver, output):
    source = (driver / 'airoha_npu.c').read_text()
    names = ['__airoha_npu_send_msg', 'airoha_npu_send_msg',
             'airoha_npu_wlan_short_guard_ready', 'airoha_npu_wlan_msg_send',
             'airoha_npu_wlan_msg_get']
    constants = ['AIROHA_NPU_MBOX_SIZE', 'AIROHA_NPU_MBOX_TIMEOUT_US',
                 'NPU_MBOX_BASE_ADDR', 'REG_CR_MBQ0_CTRL',
                 'MBOX_MSG_FUNC_ID', 'MBOX_MSG_STATIC_BUF', 'MBOX_MSG_STATUS',
                 'MBOX_MSG_DONE', 'MBOX_MSG_WAIT_RSP']
    definitions = []
    for name in constants:
        match = re.search(r'^#define ' + re.escape(name) + r'(?:\([^\n]*?\))?\s+[^\n]+',
                          source, re.MULTILINE)
        assert match, name
        definitions.append(match.group())
    for first in ['NPU_OP_SET', 'NPU_FUNC_WIFI', 'NPU_MBOX_ERROR']:
        match = re.search(r'enum \{\n\s*' + first + r'\b[^}]+\};', source)
        assert match, first
        definitions.append(match.group())
    match = re.search(r'struct wlan_mbox_data \{[^}]+\};', source)
    assert match
    definitions.append(match.group())
    (output / 'production_constants.h').write_text('\n'.join(definitions) + '\n')
    for name in names:
        (output / (name + '.inc')).write_text(extract_function(source, name))
    assert source.index('#include "airoha_npu_er_provider.h"') < source.index(names[0])
    assert '#include "airoha_npu_er_provider.h"' not in (driver / 'airoha_npu_transaction.inc').read_text()
    return names


def main():
    parser = argparse.ArgumentParser(description='Test the production core0 sender after applying ZH to ZG.')
    parser.add_argument('--source', type=Path, required=True, help='Kernel tree already containing 999-zg')
    parser.add_argument('--output', type=Path, required=True, help='New output directory outside the ponwrt repository')
    parser.add_argument('--patched', action='store_true', help='Source already includes 999-zh; skip patch application')
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    patch = repo / 'target/linux/airoha/patches-6.18/999-zh-net-airoha-quarantine-ambiguous-mailbox.patch'
    output = args.output.resolve()
    assert not output.is_relative_to(repo), 'output must be outside the ponwrt repository'
    output.mkdir(parents=True, exist_ok=False)
    tree = output / 'kernel'
    relative = Path('drivers/net/ethernet/airoha')
    driver = tree / relative
    driver.mkdir(parents=True)
    files = ['airoha_npu.c', 'airoha_npu_transaction.inc', 'airoha_npu_er_provider.h',
             'airoha_npu_transaction.h', 'npu_eth_return_abi.h',
             'npu_auth_mailbox_abi.h', 'npu_bank1_gate_abi.h']
    base_hashes = {}
    for name in files:
        source = args.source / relative / name
        base_hashes[name] = digest(source)
        shutil.copyfile(source, driver / name)
    assert patch.read_text().startswith('From: Enceka <enceka@yeah.net>\n')
    assert 'Signed-off-by:' not in patch.read_text()
    if not args.patched:
        applied = run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                       '-p1', '-i', str(patch)], output, 'apply', cwd=tree)
        assert 'fuzz' not in applied and 'offset' not in applied, applied
    shim = output / 'shim/linux/mutex.h'
    shim.parent.mkdir(parents=True)
    shim.write_text('''#ifndef TEST_MUTEX_H
#define TEST_MUTEX_H
struct mutex { pthread_mutex_t native; };
static inline void mutex_init(struct mutex *lock)
{ assert(!pthread_mutex_init(&lock->native, NULL)); }
static inline void mutex_lock(struct mutex *lock)
{ assert(!pthread_mutex_lock(&lock->native)); }
static inline void mutex_unlock(struct mutex *lock)
{ assert(!pthread_mutex_unlock(&lock->native)); }
#define lockdep_assert_held(lock) ((void)(lock))
#endif
''')
    names = extract(driver, output)
    hashes = {name: digest(driver / name) for name in files}
    build = [args.cc, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
             '-pthread', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-I', str(output / 'shim'), '-I', str(driver), '-I', str(output),
             str(tests / 'mailbox_test.c')]
    results = {}
    for mode, flags in [('native', []), ('swapped', ['-DTEST_SWAPPED_ENDIAN'])]:
        binary = output / mode
        run(build + flags + ['-o', str(binary)], output, mode + '-build')
        results[mode] = run([str(binary)], output, mode, cwd=output, timeout=30)
    sender = output / '__airoha_npu_send_msg.inc'
    ready = output / 'airoha_npu_wlan_short_guard_ready.inc'
    transport = driver / 'airoha_npu_transaction.inc'
    mutations = {
        'allow_after_quarantine': (sender, 'if (READ_ONCE(instance->transport_quarantined))', 'if (false)'),
        'omit_quarantine_latch': (sender, 'WRITE_ONCE(instance->transport_quarantined, true);',
                                'WRITE_ONCE(instance->transport_quarantined, false);'),
        'omit_guard_withdrawal': (sender, 'WRITE_ONCE(npu->wlan_short_guard_verified, false);',
                                 'WRITE_ONCE(npu->wlan_short_guard_verified, true);'),
        'omit_response_barrier': (sender, '\t\tdma_rmb();', '\t\t(void)0;'),
        'preserve_old_done': (sender, 'FIELD_PREP(MBOX_MSG_FUNC_ID, func_id) | MBOX_MSG_WAIT_RSP;',
                              'FIELD_PREP(MBOX_MSG_FUNC_ID, func_id) | MBOX_MSG_WAIT_RSP | MBOX_MSG_DONE;'),
        'skip_done_readback_check': (sender, 'if (val & MBOX_MSG_DONE)', 'if (false)'),
        'retry_ambiguous_trigger': (sender, 'val + 1);\n\tif (ret)\n\t\tgoto quarantine;',
                                   'val + 1);\n\tif (ret)\n\t\tgoto unlock;'),
        'ignore_address_error': (sender, 'core->addr);\n\tif (ret)\n\t\tgoto unlock;',
                                 'core->addr);\n\tif (false)\n\t\tgoto unlock;'),
        'revive_guard': (ready, '!READ_ONCE(instance->transport_quarantined) &&',
                         '(READ_ONCE(instance->transport_quarantined) || true) &&'),
        'retire_on_error': (transport, 'if (!err)\n\t\t\tairoha_npu_er_complete',
                            'if (true)\n\t\t\tairoha_npu_er_complete'),
    }
    caught = {}
    for name, (path, before, after) in mutations.items():
        original = path.read_text()
        assert original.count(before) == 1, name
        try:
            path.write_text(original.replace(before, after))
            binary = output / name
            run(build + ['-o', str(binary)], output, name + '-build')
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    cwd=output, timeout=30)
            (output / (name + '.log')).write_text(result.stdout + result.stderr)
            assert result.returncode, 'missed mutation: ' + name
            assert 'Assertion' in result.stderr or 'assertion' in result.stderr, name
            caught[name] = result.returncode
        finally:
            path.write_text(original)
    assert all(digest(args.source / relative / name) == base_hashes[name] for name in files)
    report = {'passed': True, 'base_source': str(args.source.resolve()), 'already_patched': args.patched,
              'base_sha256': base_hashes, 'source_sha256': hashes,
              'patch_sha256': digest(patch), 'extracted_functions': names,
              'tests_sha256': {name: digest(tests / name) for name in ['verify.py', 'mailbox_test.c']},
              'modes': results, 'caught_mutations': caught}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
