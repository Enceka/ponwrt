#!/usr/bin/env python3
"""Apply ZZ4 exactly to a separate source copy and exercise real PPE functions."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import HUNK, SourceBinding, exact_hunks

DRIVER = Path('drivers/net/ethernet/airoha')
PATCH = '999-zz4-net-airoha-snapshot-pon-flow-candidates.patch'
PREVIOUS = '999-zz3-net-airoha-admit-observed-pon-software-candidates.patch'
TARGETS = ('airoha_eth.h', 'airoha_ppe.c')
FUNCTIONS = (
    'airoha_ppe_foe_compare_entry', 'airoha_ppe_ct_pon_row_matches',
    'airoha_ppe_ct_remove_pon_flow', 'airoha_ppe_ct_pon_flow',
    'airoha_ppe_ct_pon_dev_ready', 'airoha_ppe_pon_candidate_read_locked',
    'airoha_ppe_pon_candidate_snapshot', 'airoha_ppe_pon_candidate_validate',
    'airoha_ppe_pon_candidate_put', 'airoha_ppe_foe_flow_commit_entry',
    'airoha_ppe_ct_bridge_publish', 'airoha_ppe_flow_offload_destroy',
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def block(text, pattern, semicolon=False):
    matches = list(re.finditer(pattern, text, re.M))
    assert len(matches) == 1, pattern
    start = matches[0].start()
    position = text.index('{', start) + 1
    depth = 1
    while depth:
        depth += (text[position] == '{') - (text[position] == '}')
        position += 1
    if semicolon:
        assert text[position] == ';'
        position += 1
    return text[start:position] + '\n'


def reverse_section(section):
    lines = section.splitlines(True)
    result = [lines[0].replace('--- a/', '--- b/', 1),
              lines[1].replace('+++ b/', '+++ a/', 1)]
    for line in lines[2:]:
        match = HUNK.match(line)
        if match:
            line = '@@ -' + match[3] + ',' + (match[4] or '1') + ' +' + match[1] + ',' + (match[2] or '1') + ' @@\n'
        elif line.startswith('+'):
            line = '-' + line[1:]
        elif line.startswith('-'):
            line = '+' + line[1:]
        result.append(line)
    return ''.join(result)


def generated_abi(text):
    pieces = []
    for marker in ('AIROHA_FOE_STATE_INVALID', 'PPE_PKT_TYPE_IPV4_HNAPT', 'AIROHA_DEV_F_WAN', 'FLOW_TYPE_L4'):
        pieces.append(block(text, r'^enum[^\n{]*\{(?=\s*' + marker + r'\b)', True))
    pieces += [line + '\n' for line in text.splitlines()
               if re.match(r'#define (?:AIROHA_FOE_IB1_BIND_\w+|AIROHA_PON_QDMA_\w+|PPE_ENTRY_SIZE)\b', line)]
    structures = (
        'airoha_foe_mac_info_common', 'airoha_foe_mac_info', 'airoha_foe_bridge',
        'airoha_foe_l2b', 'airoha_foe_ipv4_tuple', 'airoha_foe_ipv4',
        'airoha_foe_ipv4_dslite', 'airoha_foe_ipv6', 'airoha_foe_entry',
        'airoha_foe_stats64', 'airoha_ct_bridge_peer', 'airoha_flow_table_entry',
        'airoha_pon_flow_entry', 'airoha_pon_flow_table', 'airoha_pon_candidate_snapshot',
    )
    pieces += [block(text, r'^struct ' + name + r'\s*(?=\{)', True) for name in structures]
    pieces += [line + '\n' for line in text.splitlines() if line.startswith('static_assert(')]
    for name in ('snapshot', 'validate', 'put'):
        matches = re.findall(r'^(?:int|void) airoha_ppe_pon_candidate_' + name + r'\([^;]+;', text, re.M)
        assert len(matches) == 1, name
        pieces.append(matches[0] + '\n')
    ppe = block(text, r'^struct airoha_ppe \{', True)
    assert ppe.count('u64 pon_candidate_serial;') == 1
    return '\n'.join(pieces)


def mutations():
    return (
        ('aba', 'observed.serial != snapshot->serial ||', 'false ||'),
        ('generation', 'observed.generation != snapshot->generation ||', 'false ||'),
        ('mapping-tag', 'observed.mapping.tag != snapshot->mapping.tag ||', 'false ||'),
        ('mapping-vlan', 'observed.mapping.vlan_id != snapshot->mapping.vlan_id ||', 'false ||'),
        ('mapping-pbit', 'observed.mapping.pbit_mask != snapshot->mapping.pbit_mask ||', 'false ||'),
        ('actions', '!airoha_ppe_ct_pon_row_matches(entry, &snapshot->data)', 'false'),
        ('raw-state-comparison', '!airoha_ppe_ct_pon_row_matches(entry, &snapshot->data)',
         'memcmp(&entry->data, &snapshot->data, sizeof(entry->data))'),
        ('seen', '!entry->pon_ingress_seen ||', 'false ||'),
        ('conflict', 'entry->pon_ingress_conflict ||', 'false ||'),
        ('bound-row', 'entry->hash != 0xffff ||', 'false ||'),
        ('epon', '(mapping_entry->tag & AIROHA_PON_QDMA_EPON) ||', 'false ||'),
        ('overflow', 'e->pon_candidate && ppe->pon_candidate_serial == U64_MAX', 'false'),
        ('cookie-rollback', 'if (err)\n\t\trhashtable_remove_fast', 'if (false)\n\t\trhashtable_remove_fast'),
        ('ingress-ref', 'dev_hold(next.ingress);', '(void)next.ingress;'),
        ('egress-ref', 'dev_hold(next.egress);', '(void)next.egress;'),
        ('partial-output', 'spin_unlock_bh(&ppe_lock);\n\treturn error;\n}\n\nint airoha_ppe_pon_candidate_validate',
         '*snapshot = next;\n\tspin_unlock_bh(&ppe_lock);\n\treturn error;\n}\n\nint airoha_ppe_pon_candidate_validate'),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to(REPOSITORY) or output.is_relative_to(source) or source.is_relative_to(output):
        parser.error('output must be new, outside ponwrt and separate from source')
    output.mkdir(parents=True)
    temporary = output / 'tmp'
    temporary.mkdir()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = {**os.environ, 'TMPDIR': str(temporary),
                   'ASAN_OPTIONS': 'halt_on_error=1:abort_on_error=1',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    commands = []

    def run(command, label, required=True):
        command = list(map(str, command))
        commands.append(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, env=environment)
        (output / (label + '.log')).write_text(result.stdout + result.stderr)
        if required and result.returncode:
            raise RuntimeError(label + ':\n' + result.stdout + result.stderr)
        return result

    inputs = {source / DRIVER / name: (source / DRIVER / name).read_bytes() for name in TARGETS}
    inputs.update({path: path.read_bytes() for path in HERE.iterdir() if path.is_file()})
    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    for patch_name in (PREVIOUS, PATCH):
        path = binding.patches / patch_name
        inputs[path] = binding.snapshot[patch_name]
    kernel = output / 'kernel'
    driver = kernel / DRIVER
    shutil.copytree(source / DRIVER, driver)
    sections = list(binding.sections(binding.snapshot[PREVIOUS], TARGETS))
    assert {name for name, added, section in sections} == set(TARGETS)
    previous = output / 'zz3-replay.patch'
    previous.write_text(''.join(section for name, added, section in sections))
    for name, added, section in sections:
        assert not added
        exact_hunks((driver / name).read_bytes(), reverse_section(section))
    for reverse in (True, False):
        if not reverse:
            for name, added, section in sections:
                exact_hunks((driver / name).read_bytes(), section)
        result = run(['patch', '--batch', '--fuzz=0', '--no-backup-if-mismatch',
                      '-R' if reverse else '--forward', '-p1', '-d', kernel, '-i', previous],
                     'zz3-reverse' if reverse else 'zz3-replay')
        assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    for name in TARGETS:
        assert (driver / name).read_bytes() == inputs[source / DRIVER / name]
    sections = list(binding.sections(binding.snapshot[PATCH], TARGETS))
    assert re.findall(r'^\+\+\+ b/(.+)$', binding.snapshot[PATCH].decode(), re.M) == [str(DRIVER / name) for name in TARGETS]
    for name, added, section in sections:
        assert not added
        exact_hunks((driver / name).read_bytes(), section)
    result = run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                  '-p1', '-d', kernel, '-i', binding.patches / PATCH], 'apply')
    assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    print('PASS exact ZZ3 reverse/replay and ZZ4 application', flush=True)
    text = (driver / 'airoha_ppe.c').read_text()
    functions = {name: block(text, r'^(?:static )?(?:bool|int|void) ' + name + r'\(') for name in FUNCTIONS}
    production = '\n'.join(functions.values())
    (output / 'production.inc').write_text(production)
    (output / 'production_abi.h').write_text(generated_abi((driver / 'airoha_eth.h').read_text()))
    compiler = shlex.split(args.cc)
    version = run(compiler + ['--version'], 'compiler').stdout
    flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow',
             '-Wstrict-prototypes', '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-I', output, '-I', HERE, HERE / 'snapshot_test.c']

    def build_run(label, args=()):
        binary = output / label
        run(compiler + flags + ['-o', binary], label + '-build')
        return run([binary, *args], label, required=False)

    result = build_run('snapshot')
    assert not result.returncode, result.stdout + result.stderr
    baseline = json.loads(result.stdout)
    assert baseline['passed'] and baseline['holds'] == baseline['puts']
    print('PASS snapshot ' + result.stdout.strip(), flush=True)
    lock_tests = {}
    for name in ('snapshot-unlocked', 'validate-unlocked'):
        result = run([output / 'snapshot', name], name, required=False)
        assert result.returncode == 1 and 'CHECK failed [missing mutex rejected]' in result.stderr, result.stderr
        lock_tests[name] = result.stderr.strip()
    caught = {}
    for name, old, new in mutations():
        assert production.count(old) == 1, name
        try:
            (output / 'production.inc').write_text(production.replace(old, new, 1))
            result = build_run('mutant-' + name)
            assert result.returncode == 1 and 'CHECK failed [' in result.stderr, (name, result.stdout, result.stderr)
            assert not re.search(r'Sanitizer|runtime error:', result.stderr), (name, result.stderr)
            caught[name] = result.stderr.strip()
        finally:
            (output / 'production.inc').write_text(production)
    compile_mutants = {}
    for identifier in ('mapping_entry', 'observed'):
        label = 'kernel-current-' + identifier
        try:
            changed = re.sub(r'\b' + identifier + r'\b', 'current', production)
            assert changed != production
            (output / 'production.inc').write_text(changed)
            result = run(compiler + flags + ['-fsyntax-only'], label, required=False)
            assert result.returncode and 'get_current' in result.stderr and 'error:' in result.stderr, result.stderr
            compile_mutants[label] = {'rejected': True, 'log': str(output / (label + '.log'))}
        finally:
            (output / 'production.inc').write_text(production)
    for path, data in inputs.items():
        assert path.read_bytes() == data, 'input changed: ' + str(path)
    report = {
        'passed': True, 'source': str(source), 'baseline': baseline,
        'binding': {'zz3_reverse_replay': True, 'zz4_exact_application': True, 'fuzz': 0, 'offset': 0},
        'lock_tests': lock_tests, 'mutants': caught, 'compile_mutants': compile_mutants,
        'sanitizers': ['address', 'undefined'],
        'patch_sha256': digest(binding.snapshot[PATCH]),
        'inputs_sha256': {str(path): digest(data) for path, data in inputs.items()},
        'patched_sha256': {name: digest((driver / name).read_bytes()) for name in TARGETS},
        'functions_sha256': {name: digest(body.encode()) for name, body in functions.items()},
        'compiler': version, 'commands': commands,
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS lock contracts and ' + str(len(caught)) + ' runtime mutants', flush=True)
    print('PASS ' + str(len(compile_mutants)) + ' kernel current macro compile mutants', flush=True)
    print('PASS report: ' + str(output / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
