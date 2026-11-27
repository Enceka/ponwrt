#!/usr/bin/env python3
"""Compile production bank1 retirement and cookie reuse paths with fault injection."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import subprocess


HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
DRIVER = Path('drivers/net/ethernet/airoha')
HEADER = 'airoha_npu_bank1.h'
PATCH = '999-zc-net-airoha-retire-host-bank1-before-npu-reuse.patch'
REUSE_FUNCTIONS = (
    'airoha_ppe_foe_compare_entry',
    'airoha_ppe_foe_remove_flow',
    'airoha_ppe_foe_remove_l2_flow',
    'airoha_ppe_foe_flow_remove_entry',
    'airoha_ppe_ct_pon_row_matches',
    'airoha_ppe_ct_remove_pon_flow',
    'airoha_ppe_ct_wlan_dest',
    'airoha_ppe_ct_wlan_entry',
    'airoha_ppe_ct_bridge_row_matches',
    'airoha_ppe_ct_remove_wlan_flow_locked',
    'airoha_ppe_ct_remove_wlan_flow',
    'airoha_ppe_ct_pon_flow',
    'airoha_ppe_get_entry_idle_time',
    'airoha_ppe_foe_flow_l2_entry_update',
    'airoha_ppe_foe_flow_entry_update',
    'airoha_ppe_entry_idle_time',
    'airoha_ppe_flow_offload_destroy',
    'airoha_ppe_flow_offload_stats',
)


def function(source, name):
    matches = list(re.finditer(r'^static [^;{}]*\b' + re.escape(name) +
                              r'\([^;{}]*\)\n\{', source, re.M))
    if len(matches) != 1:
        raise ValueError('expected one production function: ' + name)
    start, end = matches[0].start(), matches[0].end()
    depth = 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise ValueError('unterminated production function: ' + name)
    return source[start:end] + '\n'


def new_header(patch):
    lines = patch.splitlines(keepends=True)
    marker = ('+++ b/' + str(DRIVER / HEADER) + '\n').encode()
    if lines.count(marker) != 1:
        raise ValueError('patch must contain exactly one bank1 header')
    start = lines.index(marker)
    if lines[start - 1] != b'--- /dev/null\n':
        raise ValueError('bank1 header must be a newly added file')
    match = re.fullmatch(rb'@@ -0,0 \+1,(\d+) @@\n', lines[start + 1])
    if not match:
        raise ValueError('expected complete new-file hunk')
    count = int(match.group(1))
    body = lines[start + 2:start + 2 + count]
    if len(body) != count or any(not line.startswith(b'+') for line in body):
        raise ValueError('invalid new-header hunk length or content')
    return b''.join(line[1:] for line in body)


def section(source, start, end):
    begin = source.index(start)
    return source[begin:source.index(end, begin)]


def production_types(header, registers):
    macros = ('PPE_SRAM_NUM_ENTRIES', 'PPE_DRAM_NUM_ENTRIES', 'PPE_ENTRY_SIZE')
    register_macros = ('PPE1_BASE', 'PPE2_BASE', 'REG_PPE_RAM_CTRL',
                       'PPE_SRAM_CTRL_ACK_MASK', 'PPE_SRAM_CTRL_DUAL_SUCESS_MASK',
                       'PPE_SRAM_CTRL_ENTRY_MASK', 'PPE_SRAM_WR_DUAL_DIRECTION_MASK',
                       'PPE_SRAM_CTRL_WR_MASK', 'PPE_SRAM_CTRL_REQ_MASK')
    result = ''
    for source, names in ((header, macros), (registers, register_macros)):
        for name in names:
            matches = re.findall(r'^#define ' + name + r'(?=\s|\().*$', source, re.M)
            if len(matches) != 1:
                raise ValueError('expected production constant: ' + name)
            result += matches[0] + '\n'
    result += section(header, 'enum {\n\tAIROHA_FOE_STATE_INVALID,', 'struct airoha_flow_data {')
    result += section(header, 'enum airoha_flow_entry_type {', 'struct airoha_wdma_info {')
    result += section(header, 'enum {\n\tFE_PSE_PORT_CDM1,', '};') + '};\n'
    result += section(header, 'enum airoha_dev_flags {', '};') + '};\n'
    return result


def mutants(header, ack, reuse):
    edits = {
        'include-bank0-boundary': ('header', 'hash >= PPE_SRAM_NUM_ENTRIES', 'hash >= PPE_SRAM_NUM_ENTRIES - 1'),
        'include-upper-boundary': ('header', 'hash < 2 * PPE_SRAM_NUM_ENTRIES', 'hash <= 2 * PPE_SRAM_NUM_ENTRIES'),
        'leave-candidate-linked': ('header', '\thlist_del_init(&entry->list);', '\t(void)entry;'),
        'retain-old-cookie-hash': ('header', 'entry->hash = 0xffff;', '(void)entry;'),
        'retain-old-ib1-state': ('header', 'entry->data.ib1 &= ~AIROHA_FOE_IB1_BIND_STATE;', '(void)entry;'),
        'leave-bridge-alive': ('header', 'entry->ct_bridge_dead = true;', 'entry->ct_bridge_dead = false;'),
        'free-bank0-l2-child': ('header', 'if (!airoha_ppe_bank1_hash(subflow->hash))', 'if (false)'),
        'leave-bank1-l2-child-linked': ('header', 'hlist_del_init(&subflow->l2_subflow_node);', '(void)subflow;'),
        'leak-bank1-l2-child': ('header', 'kfree(subflow);', '(void)subflow;'),
        'lose-resize-deduplication': ('header', 'if (list_empty(&entry->gc_node))', 'if (true)'),
        'treat-eagain-as-hard-error': ('header', 'if (PTR_ERR(entry) == -EAGAIN)', 'if (false)'),
        'ignore-hard-walk-error': ('header', 'error = PTR_ERR(entry);', 'error = 0;'),
        'retire-after-hard-walk-error': ('header', '\t\tif (error)\n\t\t\tcontinue;', '\t\tif (false)\n\t\t\tcontinue;'),
        'leave-gc-node-linked': ('header', 'list_del_init(&entry->gc_node);', '(void)entry;'),
        'detach-without-ppe-lock': ('header', '\t\tspin_lock_bh(&ppe_lock);\n\t\tairoha_ppe_bank1_detach_entry(entry);', '\t\tairoha_ppe_bank1_detach_entry(entry);\n\t\tspin_lock_bh(&ppe_lock);'),
        'reschedule-under-ppe-lock': ('header', '\t\tairoha_ppe_bank1_detach_entry(entry);\n\t\tspin_unlock_bh(&ppe_lock);', '\t\tairoha_ppe_bank1_detach_entry(entry);\n\t\tcond_resched();\n\t\tspin_unlock_bh(&ppe_lock);'),
        'ignore-sram-ownership': ('header', '!ppe->ct_owns_sram ||', 'false ||'),
        'clear-bank0': ('header', 'u32 hash = PPE_SRAM_NUM_ENTRIES + *next_row;', 'u32 hash = *next_row;'),
        'clear-only-ib1': ('header', 'memset(entry, 0, sizeof(*entry));', 'memset(entry, 0, sizeof(entry->ib1));'),
        'ignore-commit-error': ('header', 'error = airoha_ppe_foe_commit_sram_entry(ppe, hash);', '(void)airoha_ppe_foe_commit_sram_entry(ppe, hash);\n\t\terror = 0;'),
        'skip-write-ack': ('header', '!airoha_ppe_ct_sram_ack(ppe->eth, hash, true)', 'false'),
        'skip-read-ack': ('header', '!airoha_ppe_ct_sram_ack(ppe->eth, hash, false)', 'false'),
        'compare-only-ib1': ('header', 'memcmp(entry, &invalid, sizeof(invalid))', 'memcmp(entry, &invalid, sizeof(invalid.ib1))'),
        'advance-failed-cursor': ('header', '\t\tif (error)\n\t\t\treturn error;', '\t\tif (error) {\n\t\t\t++*next_row;\n\t\t\treturn error;\n\t\t}'),
        'advance-cursor-under-lock': ('header', '\t\tspin_unlock_bh(&ppe_lock);\n\t\tif (error)', '\t\t++*next_row;\n\t\tspin_unlock_bh(&ppe_lock);\n\t\tif (error)'),
        'accept-ack-wrong-row': ('ack', 'return (ctrl & mask) == expected;', 'return (ctrl & (mask & ~PPE_SRAM_CTRL_ENTRY_MASK)) == (expected & ~PPE_SRAM_CTRL_ENTRY_MASK);'),
        'accept-ack-wrong-direction': ('ack', 'return (ctrl & mask) == expected;', 'return (ctrl & (mask & ~PPE_SRAM_CTRL_WR_MASK)) == (expected & ~PPE_SRAM_CTRL_WR_MASK);'),
        'accept-ack-request-still-set': ('ack', 'return (ctrl & mask) == expected;', 'return (ctrl & (mask & ~PPE_SRAM_CTRL_REQ_MASK)) == (expected & ~PPE_SRAM_CTRL_REQ_MASK);'),
    }
    sources = {'header': header, 'ack': ack, 'reuse': reuse}
    for name, (target, old, new) in edits.items():
        if sources[target].count(old) != 1:
            raise ValueError('mutant must match exactly once: ' + name)
        modified = dict(sources)
        modified[target] = modified[target].replace(old, new, 1)
        yield name, modified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--patch', type=Path, default=REPOSITORY / 'target/linux/airoha/patches-6.18' / PATCH)
    parser.add_argument('--output', type=Path, default=HERE / '_results' / datetime.now().strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    driver = args.source.resolve() / DRIVER
    inputs = {driver / name: (driver / name).read_bytes() for name in
              (HEADER, 'airoha_ppe.c', 'airoha_eth.h', 'airoha_regs.h')}
    inputs[args.patch.resolve()] = args.patch.read_bytes()
    header = inputs[driver / HEADER]
    patch_header = new_header(inputs[args.patch.resolve()])
    if header != patch_header:
        raise ValueError('production header differs byte-for-byte from 999-zc added header')
    ppe = inputs[driver / 'airoha_ppe.c'].decode()
    ack = function(ppe, 'airoha_ppe_ct_sram_ack')
    reuse = '\n'.join(function(ppe, name) for name in REUSE_FUNCTIONS)
    types = production_types(inputs[driver / 'airoha_eth.h'].decode(), inputs[driver / 'airoha_regs.h'].decode())
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'tmp'
    temporary.mkdir()
    environment = dict(os.environ, TMPDIR=str(temporary),
                       ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    compiler = shlex.split(args.cc)
    commands = []

    def run(command, directory, label):
        commands.append(command)
        result = subprocess.run(command, cwd=directory, env=environment,
                                capture_output=True, text=True, timeout=120)
        (directory / (label + '.log')).write_text(result.stdout + result.stderr)
        return result

    version = run(compiler + ['--version'], output, 'compiler')
    if version.returncode:
        raise RuntimeError(version.stderr)
    print(version.stdout.splitlines()[0], flush=True)
    print('PASS byte-exact production header / 999-zc: ' + hashlib.sha256(header).hexdigest(), flush=True)

    def build_run(label, sources):
        directory = output / label
        directory.mkdir()
        (directory / HEADER).write_bytes(sources['header'].encode())
        (directory / 'production_ack.inc').write_text(sources['ack'])
        (directory / 'production_reuse.inc').write_text(sources['reuse'])
        (directory / 'production_types.inc').write_text(types)
        executable = directory / 'bank1_test'
        command = compiler + ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                              '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                              '-fno-omit-frame-pointer', '-I', str(directory),
                              str(HERE / 'bank1_test.c'), '-o', str(executable)]
        build = run(command, directory, 'build')
        if build.returncode:
            raise RuntimeError('BUILD FAILED (never a killed mutant): ' + label + '\n' + build.stderr)
        return run([str(executable)], directory, 'run')

    baseline_sources = {'header': header.decode(), 'ack': ack, 'reuse': reuse}
    baseline = build_run('baseline', baseline_sources)
    if baseline.returncode:
        raise RuntimeError('baseline failed:\n' + baseline.stdout + baseline.stderr)
    summary = json.loads(baseline.stdout)
    print('PASS baseline ' + baseline.stdout.strip(), flush=True)
    detected = []
    for name, sources in mutants(**baseline_sources):
        result = build_run(name, sources)
        if result.returncode != 1 or 'CHECK failed:' not in result.stderr:
            raise RuntimeError('mutant requires runtime CHECK failure: ' + name + '\n' + result.stdout + result.stderr)
        detected.append({'name': name, 'exit_code': result.returncode, 'assertion': result.stderr.strip()})
        print('PASS runtime mutant ' + name, flush=True)
    for path, content in inputs.items():
        if path.read_bytes() != content:
            raise RuntimeError('production input changed during run: ' + str(path))
    report = {
        'passed': True, 'baseline': summary, 'sanitizers': ['address', 'undefined'],
        'header_byte_exact_to_patch': True,
        'inputs_sha256': {str(path): hashlib.sha256(content).hexdigest() for path, content in inputs.items()},
        'tests_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                         for path in HERE.iterdir() if path.is_file()},
        'reuse_functions': list(REUSE_FUNCTIONS), 'negative_controls': detected,
        'compiler': version.stdout, 'commands': commands,
        'scope': 'Unmodified production bank1 header, ACK validator, full stats/destroy functions and their selected callees; kernel containers, clock, locks, MMIO and statistics transport are host stubs. Owner integration and kernel build run separately.',
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS ' + str(len(detected)) + ' runtime-assertion mutants; report: ' + str(output / 'report.json'))


if __name__ == '__main__':
    main()
