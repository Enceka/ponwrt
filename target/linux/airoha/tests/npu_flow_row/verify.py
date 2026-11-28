#!/usr/bin/env python3
"""Apply ZZ5 exactly and exercise shared row operations through real diag callers."""

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
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks

SPEC = importlib.util.spec_from_file_location('diag_runner', HERE.parent / 'npu_diag/verify.py')
DIAG = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAG)
PATCH = '999-zz5-net-airoha-share-checked-pon-bank0-row-operations.patch'
DRIVER = Path('drivers/net/ethernet/airoha')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.is_relative_to(REPOSITORY) or output.is_relative_to(source) or source.is_relative_to(output):
        parser.error('output must be new and outside the repository and source')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    paths = [path for path in source.rglob('*') if path.is_file()]
    paths += [HERE / 'verify.py', HERE / 'row_test.c', HERE / 'README.md',
              HERE.parent / 'npu_diag/diag_test.c', HERE.parent / 'npu_diag/verify.py',
              HERE.parent / 'npu_ingress/source_binding.py']
    originals = {path: digest(path.read_bytes()) for path in paths}
    output.mkdir(parents=True, exist_ok=False)
    tree = output / 'candidate'
    shutil.copytree(source, tree)
    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    sections = list(binding.sections(binding.snapshot[PATCH], ('airoha_npu_diag.h', 'airoha_npu_flow_row.h')))
    assert {name for name, added, section in sections} == {'airoha_npu_diag.h', 'airoha_npu_flow_row.h'}
    for name, added, section in sections:
        target = tree / DRIVER / name
        assert not added or not target.exists(), name
        exact_hunks(b'' if added else target.read_bytes(), section)
    commands = []
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')

    def run(command, label, cwd=None, required=True, text=None):
        command = list(map(str, command))
        commands.append(command)
        result = subprocess.run(command, cwd=cwd, env=environment, input=text,
                                capture_output=True, text=True, timeout=60)
        (output / (label + '.log')).write_text(result.stdout + result.stderr)
        if required:
            assert not result.returncode, label + '\n' + result.stdout + result.stderr
        return result

    applied = run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'], 'apply', cwd=tree,
                  text=binding.snapshot[PATCH].decode())
    assert not re.search(r'fuzz|offset|FAILED', applied.stdout + applied.stderr, re.I)
    driver = tree / DRIVER
    binding.bind(driver, ('airoha_npu_diag.h', 'airoha_npu_flow_row.h', 'airoha_npu_owner.h',
                         'airoha_npu_reopen.h', 'airoha_bank1_routes.h', 'airoha_npu_bank1.h',
                         'airoha_npu_admission.h', 'airoha_npu_auth_publish.h'))
    extracted = output / 'extracted'
    extracted.mkdir()
    function_hashes = {}
    for name, functions in DIAG.FUNCTIONS.items():
        content = (driver / name).read_text()
        for target, symbol in functions.items():
            body = DIAG.function(content, symbol)
            (extracted / (target + '.inc')).write_text(body)
            function_hashes[symbol] = digest(body.encode())
    for name in (*DIAG.HEADERS, 'airoha_npu_flow_row.h'):
        shutil.copyfile(driver / name, extracted / name)
    header = (driver / 'airoha_eth.h').read_text()
    entry_start = header.index('enum {\n\tAIROHA_FOE_STATE_INVALID,')
    entry_end = header.index('struct airoha_foe_stats {', entry_start)
    data_start = header.index('struct airoha_flow_data {')
    data_end = header.index('enum airoha_flow_entry_type {', data_start)
    size = re.search(r'^#define PPE_ENTRY_SIZE\s+\d+$', header, re.M)[0]
    (extracted / 'foe_types.inc').write_text(size + '\n' + header[entry_start:entry_end] + header[data_start:data_end])
    registers = (driver / 'airoha_regs.h').read_text()
    (extracted / 'sram_masks.inc').write_text(''.join(
        re.search(r'^#define ' + name + r'\s+[^\n]+$', registers, re.M)[0] + '\n'
        for name in ('PPE_SRAM_CTRL_ACK_MASK', 'PPE_SRAM_CTRL_ENTRY_MASK',
                     'PPE_SRAM_CTRL_WR_MASK', 'PPE_SRAM_CTRL_REQ_MASK')))
    template = (HERE.parent / 'npu_diag/diag_test.c').read_text()
    for before, after in (
        ('#include "install.inc"', '#include "airoha_npu_flow_row.h"\n#include "install.inc"'),
        ('sram_events[0].cursor == PPE_SRAM_NUM_ENTRIES &&', '!sram_events[0].cursor &&'),
        ('sram_commits++;', 'CHECK(!tracked_attempt || *tracked_attempt);\n\tsram_commits++;'),
    ):
        assert template.count(before) == 1, before
        template = template.replace(before, after)
    (extracted / 'diag_reuse.c').write_text(template)
    ppe = (driver / 'airoha_ppe.c').read_text()
    for symbol in ('airoha_ppe_foe_commit_entry', 'airoha_ppe_foe_insert_entry'):
        body = DIAG.function(ppe, symbol)
        assert 'ct_npu_owner' in body and 'airoha_ppe_npu_bank0_owned(ppe)' in body
    assert (driver / 'airoha_ppe.c').read_bytes() == (source / DRIVER / 'airoha_ppe.c').read_bytes()
    compile_command = [args.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                       '-Wno-unused-function', '-Wno-unused-parameter', '-I', extracted, HERE / 'row_test.c']
    results = {}
    for label, flags in (('plain', []), ('sanitized', ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'])):
        binary = output / label
        run(compile_command + flags + ['-o', binary], label + '-build')
        result = run([binary], label)
        results[label] = [json.loads(line) for line in result.stdout.splitlines()]
        print(label + ': ' + result.stdout.strip(), flush=True)
    helper = (extracted / 'airoha_npu_flow_row.h').read_text()
    mutations = [
        ('unb-state', 'AIROHA_FOE_STATE_UNBIND', 'AIROHA_FOE_STATE_BIND'),
        ('unb-protocol', 'AIROHA_FOE_IB1_BIND_PACKET_TYPE | AIROHA_FOE_IB1_BIND_UDP', 'AIROHA_FOE_IB1_BIND_PACKET_TYPE'),
        ('unb-tuple', 'memcmp(&learned->ipv4.orig_tuple, &bound.ipv4.orig_tuple,', '0 * memcmp(&learned->ipv4.orig_tuple, &bound.ipv4.orig_tuple,'),
        ('empty-whole-row', 'memcmp(row, &invalid, sizeof(invalid))', 'memcmp(row, &invalid, sizeof(row->ib1))'),
        ('readback-whole-row', 'memcmp(row, &bound, sizeof(bound))', 'memcmp(row, &bound, sizeof(row->ib1))'),
        ('lost-dirty', '*write_attempted = true;', '*write_attempted = false;'),
        ('commit-error', 'if (error)\n\t\treturn error;', 'if (error)\n\t\treturn 0;'),
        ('write-ack', '!airoha_ppe_ct_sram_ack(ppe->eth, hash, true)', 'false'),
        ('unb-read-ack', '!airoha_ppe_ct_sram_ack(ppe->eth, hash, false))', 'false)'),
        ('late-dirty', '*write_attempted = true;\n\t*row = bound;\n\terror = airoha_ppe_foe_commit_sram_entry(ppe, hash);',
         '*row = bound;\n\terror = airoha_ppe_foe_commit_sram_entry(ppe, hash);\n\t*write_attempted = true;'),
    ]
    for symbol in ('airoha_npu_bank0_check_unbound', 'airoha_npu_bank0_install_checked'):
        original = DIAG.function(helper, symbol)
        for label, before, after in (
            ('hash', '!airoha_ppe_bank0_hash(hash)', 'false'),
            ('expected-state', 'FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, bound.ib1) != AIROHA_FOE_STATE_BIND', 'false'),
            ('expected-type', 'FIELD_GET(AIROHA_FOE_IB1_BIND_PACKET_TYPE, bound.ib1) != PPE_PKT_TYPE_IPV4_HNAPT', 'false'),
        ):
            assert original.count(before) == 1
            mutations.append((symbol + '-' + label, original, original.replace(before, after)))
    install = DIAG.function(helper, 'airoha_npu_bank0_install_checked')
    for index in (0, 1):
        before = '!airoha_ppe_ct_sram_ack(ppe->eth, hash, false)'
        offsets = [match.start() for match in re.finditer(re.escape(before), install)]
        assert len(offsets) == 2
        offset = offsets[index]
        mutations.append(('install-read-ack-' + str(index), install,
                          install[:offset] + 'false' + install[offset + len(before):]))
    caught = []
    for label, before, after in mutations:
        assert helper.count(before) == 1, label
        (extracted / 'airoha_npu_flow_row.h').write_text(helper.replace(before, after))
        binary = output / label
        run(compile_command + ['-o', binary], label + '-build')
        result = run([binary], label, required=False)
        assert result.returncode != 0 and 'assert' in result.stderr.lower(), (label, result.stdout, result.stderr)
        caught.append(label)
    (extracted / 'airoha_npu_flow_row.h').write_text(helper)
    for label, filename, before, after in (
        ('diag-bypass-unb', 'bind.inc', 'error = airoha_npu_bank0_check_unbound(ppe, hash, &bound);', 'error = 0;'),
        ('diag-forget-dirty', 'install.inc', 'if (!write_attempted)', 'if (true)'),
        ('diag-late-cleanup-marker', 'install.inc', 'owner->bank0_next_row = 0;', ''),
    ):
        target = extracted / filename
        original = target.read_text()
        assert original.count(before) == 1
        target.write_text(original.replace(before, after))
        binary = output / label
        run(compile_command + ['-o', binary], label + '-build')
        result = run([binary], label, required=False)
        assert result.returncode != 0 and 'assert' in result.stderr.lower(), (label, result.stdout, result.stderr)
        caught.append(label)
        target.write_text(original)
    binding.verify_unchanged()
    assert binding.read_patches()[PATCH] == binding.snapshot[PATCH]
    for path, expected in originals.items():
        assert digest(path.read_bytes()) == expected, 'input changed: ' + str(path)
    report = dict(passed=True, results=results, mutations=caught, source_binding=binding.report(),
                  exact_apply=dict(passed=True, fuzz=0, offset=0), source=str(source),
                  patch_sha256=digest(binding.snapshot[PATCH]), functions_sha256=function_hashes,
                  inputs_sha256={str(path): value for path, value in originals.items()}, commands=commands)
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS ' + str(len(caught)) + ' mutations; ' + str(output / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
