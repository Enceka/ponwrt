#!/usr/bin/env python3
"""Exercise ZZ7 QDMA events against an independent copy of the ZZ4+ZZ5 SDK source."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
SNAPSHOT = HERE.parent / 'npu_pon_candidate_snapshot'
spec = importlib.util.spec_from_file_location('snapshot_verify', SNAPSHOT / 'verify.py')
snapshot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(snapshot)
block = snapshot.block
DRIVER = snapshot.DRIVER
PATCH = '999-zz7-net-airoha-record-trusted-pon-unbound-events.patch'
TARGETS = ('airoha_eth.h', 'airoha_eth.c', 'airoha_ppe.c', 'airoha_npu_bank1.h')
HEADERS = ('airoha_npu_flow_observe.h', 'airoha_npu_flow_key.h',
           'airoha_npu_auth_publish.h', 'npu_auth_mailbox_abi.h')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def replace_once(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new, 1)


def fixture_stubs(text):
    text = replace_once(text, 'static int flow_offload_mutex, ppe_lock, mutex_depth, spin_depth;',
                        'static int flow_offload_mutex, ppe_lock, mutex_depth, spin_depth, rcu_depth;')
    text = replace_once(text, 'CHECK(lock == &ppe_lock && !spin_depth && mutex_depth == 1);',
                        'CHECK(lock == &ppe_lock && !spin_depth && (mutex_depth == 1 || rcu_depth == 1));')
    text = replace_once(text, 'CHECK(lock == &ppe_lock && spin_depth == 1 && mutex_depth == 1);',
                        'CHECK(lock == &ppe_lock && spin_depth == 1 && (mutex_depth == 1 || rcu_depth == 1));')
    text = replace_once(text, 'CHECK(mutex_depth == 1 && spin_depth == 1);',
                        'CHECK((mutex_depth == 1 || rcu_depth == 1) && spin_depth == 1);')
    text = replace_once(text, 'struct airoha_pon_flow_table *pon_flow_table;',
                        'struct airoha_pon_flow_table *pon_flow_table;\n\tu32 pon_qdma_tag;')
    text = replace_once(text, 'struct airoha_ppe {',
                        'struct airoha_ppe_dev { unsigned unused; };\nstruct airoha_ppe {\n\tstruct airoha_ppe_dev dev;')
    return replace_once(text, '#include "production.inc"', '#include "event_stubs.h"\n#include "production.inc"')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to(REPO) or output.is_relative_to(source) or source.is_relative_to(output):
        parser.error('output must be new, outside ponwrt and separate from source')
    output.mkdir(parents=True)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    temporary = output / 'tmp'
    temporary.mkdir()
    environment = {**os.environ, 'TMPDIR': str(temporary), 'ASAN_OPTIONS': 'halt_on_error=1:abort_on_error=1',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    commands = []

    def run(command, name, required=True):
        command = list(map(str, command))
        commands.append(command)
        result = subprocess.run(command, text=True, capture_output=True, timeout=60, env=environment)
        (output / (name + '.log')).write_text(result.stdout + result.stderr)
        if required and result.returncode:
            raise RuntimeError(name + ':\n' + result.stdout + result.stderr)
        return result

    paths = [source / DRIVER / name for name in TARGETS + HEADERS + ('airoha_regs.h',)]
    paths += list(HERE.glob('*')) + [SNAPSHOT / name for name in ('verify.py', 'host_stubs.h', 'snapshot_test.c')]
    paths += [HERE.parent / 'npu_flow_observe/frame_fixture.h', HERE.parent / 'npu_ingress/source_binding.py']
    inputs = {path: path.read_bytes() for path in paths if path.is_file()}
    binding = snapshot.SourceBinding(REPO / 'target/linux/airoha/patches-6.18', output, PATCH)
    for name in (snapshot.PATCH, PATCH):
        inputs[binding.patches / name] = binding.snapshot[name]
    kernel = output / 'kernel'
    driver = kernel / DRIVER
    shutil.copytree(source / DRIVER, driver, ignore=shutil.ignore_patterns('*.o', '*.orig', '*.cmd'))
    previous_sections = list(binding.sections(binding.snapshot[snapshot.PATCH], snapshot.TARGETS))
    replay = output / 'zz4-replay.patch'
    replay.write_text(''.join(section for name, added, section in previous_sections))
    for name, added, section in previous_sections:
        assert not added
        snapshot.exact_hunks((driver / name).read_bytes(), snapshot.reverse_section(section))
    for reverse in (True, False):
        if not reverse:
            for name, added, section in previous_sections:
                snapshot.exact_hunks((driver / name).read_bytes(), section)
        result = run(['patch', '--batch', '--fuzz=0', '--no-backup-if-mismatch',
                      '-R' if reverse else '--forward', '-p1', '-d', kernel, '-i', replay],
                     'zz4-reverse' if reverse else 'zz4-replay')
        assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    for name in snapshot.TARGETS:
        assert (driver / name).read_bytes() == inputs[source / DRIVER / name]
    for name, added, section in binding.sections(binding.snapshot[PATCH], TARGETS):
        assert not added
        snapshot.exact_hunks((driver / name).read_bytes(), section)
    assert re.findall(r'^\+\+\+ b/(.+)$', binding.snapshot[PATCH].decode(), re.M) == [str(DRIVER / name) for name in TARGETS]
    result = run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                  '-p1', '-d', kernel, '-i', binding.patches / PATCH], 'apply')
    assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    print('PASS exact SDK ZZ4 reverse/replay and ZZ7 application', flush=True)

    eth_header = (driver / 'airoha_eth.h').read_text()
    ppe = (driver / 'airoha_ppe.c').read_text()
    eth = (driver / 'airoha_eth.c').read_text()
    bank = (driver / 'airoha_npu_bank1.h').read_text()
    functions = {name: block(ppe, r'^(?:static )?(?:bool|int|void) ' + name + r'\(')
                 for name in snapshot.FUNCTIONS + ('airoha_ppe_pon_observe_frame',
                 'airoha_ppe_pon_observe_unbound', 'airoha_ppe_pon_take_unbound', 'airoha_ppe_ct_flow_bank_matches')}
    for name in ('airoha_ppe_bank0_hash', 'airoha_ppe_bank1_hash', 'airoha_ppe_bank_hash', 'airoha_ppe_bank_detach_entry'):
        functions[name] = block(bank, r'^static (?:bool|void) ' + name + r'\(')
    for name in ('airoha_qdma_pon_learnable', 'airoha_qdma_observe_pon_skb',
                 'airoha_qdma_pon_unbound_event', 'airoha_qdma_learn_skb'):
        functions[name] = block(eth, r'^static (?:bool|void) ' + name + r'\(')
    rx = block(eth, r'^static int airoha_qdma_rx_process\(')
    start = rx.index('\t\treason = FIELD_GET(AIROHA_RXD4_PPE_CPU_REASON, msg1);')
    end = rx.index('\n\n\t\tdone++;', start)
    dispatch = rx[start:end]
    assert dispatch.count('airoha_qdma_pon_unbound_event(dev, q, q->skb, msg0, msg1);') == 1
    assert eth.count('airoha_qdma_pon_unbound_event(') == 2
    assert eth.count('airoha_ppe_pon_observe_unbound(') == 1
    assert 'airoha_ppe_pon_observe_unbound' not in (driver / 'airoha_npu_return.h').read_text()
    functions['rx_dispatch'] = ('static void rx_dispatch(struct airoha_gdm_dev *dev, struct airoha_queue *q, u32 msg0, u32 msg1)\n{\n'
                                '\tu32 reason, hash = FIELD_GET(AIROHA_RXD4_FOE_ENTRY, msg1);\n' + dispatch + '\n}\n')
    production = '\n'.join(functions.values())
    (output / 'production.inc').write_text(production)
    event_type = block(eth_header, r'^struct airoha_pon_unbound_event \{', True)
    abi = event_type + snapshot.generated_abi(eth_header)
    for line in (eth_header + '\n' + (driver / 'airoha_regs.h').read_text()).splitlines():
        if re.match(r'#define (?:PPE_SRAM_NUM_ENTRIES|AIROHA_RXD4_\w+|QDMA_ETH_RXMSG_\w+)\b', line):
            abi += line + '\n'
    abi += '#define PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED 0x0f\n'
    for name in ('observe_unbound', 'take_unbound'):
        matches = re.findall(r'^(?:int|void) airoha_ppe_pon_' + name + r'\([^;]+;', eth_header, re.M)
        assert len(matches) == 1
        abi += matches[0] + '\n'
    (output / 'production_abi.h').write_text(abi)
    (output / 'host_stubs.h').write_text(fixture_stubs(inputs[SNAPSHOT / 'host_stubs.h'].decode()))
    frames = inputs[HERE.parent / 'npu_flow_observe/frame_fixture.h'].decode()
    fixture = inputs[SNAPSHOT / 'snapshot_test.c'].decode()
    fixture = fixture[:fixture.index('static void rejected(void)')]
    fixture = fixture.replace('#include "host_stubs.h"\n', '')
    fixture += ''.join(block(frames, r'^static (?:void|unsigned) ' + name + r'\(') for name in ('put16', 'put32', 'make_frame'))
    (output / 'fixture.inc').write_text(fixture)
    flags = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow',
             '-Wstrict-prototypes', '-Wno-unused-function', '-fno-omit-frame-pointer',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-I', output, '-I', HERE, '-I', driver, HERE / 'event_test.c']
    run(['clang', '--version'], 'compiler')

    def build_run(label):
        binary = output / label
        run(flags + ['-o', binary], label + '-build')
        return run([binary], label, required=False)

    result = build_run('events')
    assert not result.returncode, result.stdout + result.stderr
    baseline = json.loads(result.stdout)
    print('PASS events ' + result.stdout.strip(), flush=True)
    mutations = (
        ('software-hash', '.hardware_hash = hardware_hash,', '.hardware_hash = bucket,'),
        ('entry-hash', 'entry->pon_unbound_event = (struct airoha_pon_unbound_event) {',
         'entry->hash = hardware_hash;\n\t\tentry->pon_unbound_event = (struct airoha_pon_unbound_event) {'),
        ('rate-reason', 'FIELD_GET(AIROHA_RXD4_PPE_CPU_REASON, msg1) != PPE_CPU_REASON_HIT_UNBIND_RATE_REACHED ||', 'false ||'),
        ('sport', 'FIELD_GET(QDMA_ETH_RXMSG_SPORT_MASK, msg1) != AIROHA_GDM2_IDX ||', 'false ||'),
        ('rx-qdma', 'queue->qdma != &dev->eth->qdma[1] ||', 'false ||'),
        ('lro', 'airoha_qdma_is_lro_queue(queue) ||', 'false ||'),
        ('event-key', 'memcmp(entry->pon_ingress_key, rule.raw + 9, sizeof(entry->pon_ingress_key)) ||', 'false ||'),
        ('event-service', 'entry->pon_ingress_conflict || entry->pon_ingress_service != service ||',
         'entry->pon_ingress_conflict || false ||'),
        ('take-serial', 'entry->pon_candidate_serial != serial', 'false'),
        ('take-generation', 'entry->pon_unbound_event.generation != observed.generation ||', 'false ||'),
        ('take-key', 'memcmp(entry->pon_unbound_event.key, observed.key, sizeof(observed.key))', 'false'),
        ('remove-clear', 'memset(&e->pon_unbound_event, 0, sizeof(e->pon_unbound_event));\n\thlist_del_init',
         'hlist_del_init'),
        ('retire-clear', 'if (!bank && entry->pon_candidate)', 'if (false)'),
        ('conflict-clear', 'entry->pon_ingress_seen = false;\n\t\t\t\tmemset(&entry->pon_unbound_event, 0, sizeof(entry->pon_unbound_event));',
         'entry->pon_ingress_seen = false;'),
        ('consume-clear', 'clear:\n\tmemset(&entry->pon_unbound_event, 0, sizeof(entry->pon_unbound_event));', 'clear:;'),
    )
    caught = {}
    for name, old, new in mutations:
        try:
            (output / 'production.inc').write_text(replace_once(production, old, new))
            result = build_run('mutant-' + name)
            assert result.returncode == 1 and 'CHECK failed [' in result.stderr, (name, result.stdout, result.stderr)
            assert not re.search(r'Sanitizer|runtime error:', result.stderr), result.stderr
            caught[name] = result.stderr.strip()
        finally:
            (output / 'production.inc').write_text(production)
    lock_tests = {}
    for name in ('take-unlocked', 'publish-without-rcu'):
        result = run([output / 'events', name], name, required=False)
        assert result.returncode == 1 and 'CHECK failed [' in result.stderr, result.stderr
        lock_tests[name] = result.stderr.strip()
    for path, data in inputs.items():
        assert path.read_bytes() == data, 'input changed: ' + str(path)
    report = {'passed': True, 'source': str(source), 'baseline': baseline,
              'patch_sha256': digest(binding.snapshot[PATCH]), 'mutants': caught, 'lock_tests': lock_tests,
              'binding': {'zz4_exact_reverse_replay': True, 'zz7_exact_application': True, 'offset': 0, 'fuzz': 0},
              'sanitizers': ['address', 'undefined'], 'commands': commands,
              'inputs_sha256': {str(path): digest(data) for path, data in inputs.items()},
              'functions_sha256': {name: digest(data.encode()) for name, data in functions.items()},
              'patched_sha256': {name: digest((driver / name).read_bytes()) for name in TARGETS}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS ' + str(len(caught)) + ' runtime mutants and 2 lock negatives', flush=True)
    print('PASS report: ' + str(output / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
