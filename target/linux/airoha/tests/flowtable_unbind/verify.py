#!/usr/bin/env python3
"""Replay ZZC and test extracted kernel teardown functions on the host."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PATCH = HERE.parents[1] / 'patches-6.18/999-zzc-netfilter-drain-flowtable-before-unbinding.patch'
FILES = {
    'core': 'net/netfilter/nf_flow_table_core.c',
    'offload': 'net/netfilter/nf_flow_table_offload.c',
    'api': 'net/netfilter/nf_tables_api.c',
    'path': 'net/netfilter/nf_flow_table_path.c',
    'header': 'include/net/netfilter/nf_flow_table.h',
}
FUNCTIONS = {
    'core': (
        'flow_offload_teardown', 'nf_flow_offload_gc_step',
        'nf_flow_table_gc_run', 'nf_flow_offload_work_gc',
        'nf_flow_table_do_cleanup', 'nf_flow_table_gc_cleanup',
        'nf_flow_table_free',
    ),
    'offload': (
        'nf_flow_offload_init', 'nf_flow_offload_tuple',
        'flow_offload_tuple_add', 'flow_offload_rule_add',
        'flow_offload_bridge_stale', 'flow_offload_work_add',
        'flow_offload_tuple_del', 'flow_offload_work_del',
        'flow_offload_tuple_stats', 'flow_offload_work_stats',
        'flow_offload_work_handler', 'flow_offload_queue_work',
        'nf_flow_offload_work_alloc', 'nf_flow_offload_add',
        'nf_flow_offload_del', 'nf_flow_offload_stats',
        'nf_flow_table_offload_flush_cleanup', 'nf_flow_table_offload_flush',
        'nf_flow_table_block_setup', 'nf_flow_table_block_offload_init',
        'nf_flow_table_indr_cleanup', 'nf_flow_table_indr_offload_cmd',
        'nf_flow_table_offload_cmd', 'nf_flow_table_offload_setup',
    ),
    'api': (
        'nft_unregister_flowtable_ops', '__nft_unregister_flowtable_net_hooks',
        'nft_unregister_flowtable_net_hooks', 'nft_flowtable_unregister_trans_hook',
        'nft_hook_find_ops', 'nft_hook_find_ops_rcu', 'nft_flowtable_event',
    ),
    'path': ('nft_flowtable_find_dev',),
}


def function(source, name):
    pattern = r'^(?:static )?[^;{}\n]+(?:\n)?\b' + name + r'\([^;{}]*\)\n\{'
    matches = list(re.finditer(pattern, source, re.M))
    assert len(matches) == 1, name
    start = matches[0].start()
    position = source.index('{', start) + 1
    depth = 1
    while depth:
        depth += (source[position] == '{') - (source[position] == '}')
        position += 1
    return source[start:position] + '\n'


def read_source(args, relative):
    path = args.baseline / relative
    if args.orb_machine:
        return subprocess.run(['orb', '-m', args.orb_machine, 'cat', str(path)],
                              check=True, capture_output=True, timeout=30).stdout
    return path.read_bytes()


def exact_patch(inputs, patch):
    result = dict(inputs)
    sections = re.split(r'(?m)^--- a/', patch)[1:]
    assert len(sections) == 3
    for section in sections:
        name, content = section.split('\n', 1)
        assert content.startswith('+++ b/' + name + '\n')
        original = inputs[name].decode().splitlines(keepends=True)
        modified = list(original)
        delta = 0
        hunks = list(re.finditer(r'(?m)^@@ -(\d+),(\d+) \+(\d+),(\d+) @@[^\n]*\n', content))
        assert hunks, name
        for index, match in enumerate(hunks):
            end = hunks[index + 1].start() if index + 1 < len(hunks) else len(content)
            lines = content[match.end():end].splitlines(keepends=True)
            assert all(line[0] in ' +-' for line in lines), name
            old = [line[1:] for line in lines if line[0] in ' -']
            new = [line[1:] for line in lines if line[0] in ' +']
            old_start, old_count, new_start, new_count = map(int, match.groups())
            assert (len(old), len(new)) == (old_count, new_count), (name, match.group())
            assert old_start + delta == new_start, name
            assert original[old_start - 1:old_start - 1 + old_count] == old, (name, old_start)
            modified[new_start - 1:new_start - 1 + old_count] = new
            delta += new_count - old_count
        result[name] = ''.join(modified).encode()
    assert {section.split('\n')[0] for section in sections} == {FILES[key] for key in ('core', 'offload', 'api')}
    return result


def render(sources, template):
    extracted = {}
    for group, names in FUNCTIONS.items():
        for name in names:
            extracted[name] = function(sources[FILES[group]].decode(), name)
    declarations = '\n'.join(body[:body.index('{')].rstrip() + ';'
                             for body in extracted.values())
    definitions = '\n'.join(extracted.values())
    assert template.count('@DECLARATIONS@') == template.count('@DEFINITIONS@') == 1
    return template.replace('@DECLARATIONS@', declarations).replace('@DEFINITIONS@', definitions), extracted


def patch_command(args):
    if args.patch_orb_machine:
        command = ['orb', '-m', args.patch_orb_machine, 'patch']
    else:
        command = [args.patch_tool or shutil.which('gpatch') or 'patch']
    result = subprocess.run([*command, '--version'], capture_output=True, text=True,
                            check=True, timeout=30)
    if not result.stdout.startswith('GNU patch '):
        raise RuntimeError('GNU patch is required; use --patch-tool or --patch-orb-machine. Got: '
                           + result.stdout.splitlines()[0])
    print('patch implementation: ' + result.stdout.splitlines()[0], flush=True)
    return command


def apply_real_patch(args, command, output, inputs, patch_file, label):
    kernel = output / label
    for name, content in inputs.items():
        target = kernel / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    environment = {**os.environ, 'LC_ALL': 'C', 'TMPDIR': str(output)}
    if args.patch_orb_machine:
        command = ['orb', '-m', args.patch_orb_machine, 'env', 'LC_ALL=C',
                   'TMPDIR=' + str(output), 'patch']
    applied = subprocess.run([*command, '--batch', '--forward', '--fuzz=0',
                              '--no-backup-if-mismatch', '-p1', '-d', str(kernel),
                              '-i', str(patch_file)], capture_output=True, text=True,
                             timeout=30, env=environment)
    print(label + ':\n' + applied.stdout + applied.stderr, end='', flush=True)
    return applied, {name: (kernel / name).read_bytes() for name in inputs}


def check_context_regression(args, command, output, inputs, patch, sources):
    header = '@@ -9767,9 +9768,9 @@ static int nft_flowtable_event(unsigned long event, struct net_device *dev,\n'
    previous = ('@@ -9766,10 +9767,10 @@ static int nft_flowtable_event(unsigned long event, struct net_device *dev,\n'
                ' \t\t\tif (!ops || (changename && match))\n')
    assert patch.count(header) == 1
    asymmetric = patch.replace(header, previous)
    assert exact_patch(inputs, asymmetric) == sources
    patch_file = output / 'asymmetric-context.patch'
    patch_file.write_text(asymmetric)
    result, partial = apply_real_patch(args, command, output, inputs, patch_file,
                                       'asymmetric-context-regression')
    assert result.returncode == 1
    assert 'Hunk #2 FAILED at 9767.' in result.stdout
    assert '1 out of 2 hunks FAILED' in result.stdout
    assert partial[FILES['core']] == sources[FILES['core']]
    assert partial[FILES['offload']] == sources[FILES['offload']]
    assert function(partial[FILES['api']].decode(), 'nft_flowtable_unregister_trans_hook') == function(sources[FILES['api']].decode(), 'nft_flowtable_unregister_trans_hook')
    assert function(partial[FILES['api']].decode(), 'nft_flowtable_event') == function(inputs[FILES['api']].decode(), 'nft_flowtable_event')
    print('context regression: synthetic replay accepts old hunk; GNU patch rejects it', flush=True)


def run(args, output, sources, label, flags, expected=True, selected=None):
    source, extracted = render(sources, (HERE / 'unbind_test.c').read_text())
    binary = output / label
    result = subprocess.run([args.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                             '-Werror', '-Wno-unused-parameter', '-Wno-unused-function',
                             '-Wno-sign-compare',
                             *flags, '-x', 'c', '-', '-o', str(binary)],
                            input=source, capture_output=True, text=True, timeout=60,
                            env={**os.environ, 'TMPDIR': str(output)})
    if result.returncode:
        raise RuntimeError(label + ' compile:\n' + result.stderr)
    leaks = 0 if sys.platform == 'darwin' else 1
    environment = {**os.environ, 'ASAN_OPTIONS': f'halt_on_error=1:detect_leaks={leaks}',
                   'UBSAN_OPTIONS': 'halt_on_error=1:print_stacktrace=1'}
    result = subprocess.run([str(binary), *([selected] if selected else [])],
                            capture_output=True, text=True, env=environment, timeout=30)
    if expected and result.returncode:
        raise RuntimeError(label + ':\n' + result.stdout + result.stderr)
    if not expected and (result.returncode == 0 or 'CHECK failed' not in result.stderr):
        raise RuntimeError(label + ' did not detect the regression: ' + result.stderr)
    print(label + ': ' + (result.stdout.strip() if expected else result.stderr.strip().splitlines()[-1]), flush=True)
    return extracted


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--orb-machine', help='Read baseline with orb cat; run all tests locally')
    parser.add_argument('--cc', default='clang')
    patch_options = parser.add_mutually_exclusive_group()
    patch_options.add_argument('--patch-tool', help='Local GNU patch executable; defaults to gpatch, then patch')
    patch_options.add_argument('--patch-orb-machine',
                               help='Run GNU patch against the shared host test directory; TMPDIR stays there')
    parser.add_argument('--skip-mutants', action='store_true')
    args = parser.parse_args()
    command = patch_command(args)
    inputs = {name: read_source(args, name) for name in FILES.values()}
    local_inputs = {path: path.read_bytes() for path in (PATCH, HERE / 'verify.py', HERE / 'unbind_test.c')}
    patch = local_inputs[PATCH]
    assert patch.startswith(b'From: Enceka <enceka@yeah.net>\n')
    expected_sources = exact_patch(inputs, patch.decode())
    with tempfile.TemporaryDirectory(prefix='.run-', dir=HERE) as directory:
        output = Path(directory)
        applied, sources = apply_real_patch(args, command, output, inputs, PATCH, 'kernel')
        assert applied.returncode == 0, applied.stdout + applied.stderr
        assert not re.search(r'offset|fuzz|FAILED|reversed', applied.stdout + applied.stderr, re.I)
        assert sources == expected_sources
        check_context_regression(args, command, output, inputs, patch.decode(), sources)
        print('complete ZZC replay: exact positions/context; SHA256=' + hashlib.sha256(patch).hexdigest(), flush=True)
        extracted = run(args, output, sources, 'plain', [])
        run(args, output, sources, 'sanitized', ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'])
        if not args.skip_mutants:
            run(args, output, inputs, 'baseline-regression', [], False, 'delete')
            mutations = (
                ('pending', 'core', '\tnf_flow_table_offload_flush(flowtable);\n\tmod_delayed_work', '\tmod_delayed_work', 'pending'),
                ('running-gc', 'core', '\tmod_delayed_work(system_power_efficient_wq, &flowtable->gc_work, 0);\n', '', 'running'),
                ('hook-admission', 'api', '\t\tlist_del_rcu(&hook->list);\n\t\tlist_for_each_entry(ops', '\t\tlist_for_each_entry(ops', 'hook'),
                ('reader-before-mark', 'offload', '\t\tsynchronize_net();\n\t\tnf_flow_table_gc_cleanup', '\t\tnf_flow_table_gc_cleanup', 'admission'),
                ('reader-after-mark', 'core', '\tsynchronize_net();\n\tnf_flow_table_offload_flush', '\tnf_flow_table_offload_flush', 'reader'),
                ('callback-write-lock', 'offload', '\t\tnf_flow_table_gc_cleanup(flowtable, dev);', '\t\tdown_write(&flowtable->flow_block_lock);\n\t\tnf_flow_table_gc_cleanup(flowtable, dev);\n\t\tup_write(&flowtable->flow_block_lock);', 'delete'),
                ('device-scope', 'offload', '\t\tnf_flow_table_gc_cleanup(flowtable, dev);', '\t\tnf_flow_table_gc_cleanup(flowtable, NULL);', 'hook'),
                ('namespace-scope', 'core', 'net_eq(nf_ct_net(flow->ct), dev_net(dev)) &&', 'true &&', 'scope'),
                ('netdev-admission', 'api', '\t\t\tlist_del_rcu(&ops->list);\n\t\t\tnft_unregister_flowtable_ops', '\t\t\tnft_unregister_flowtable_ops', 'netdev'),
            )
            for label, group, old, new, selected in mutations:
                mutated = dict(sources)
                content = mutated[FILES[group]].decode()
                assert content.count(old) == 1, label
                mutated[FILES[group]] = content.replace(old, new).encode()
                run(args, output, mutated, 'mutant-' + label, [], False, selected)
        for name, body in extracted.items():
            print(name + ' sha256=' + hashlib.sha256(body.encode()).hexdigest())
    assert all(read_source(args, name) == content for name, content in inputs.items()), 'baseline changed during test'
    assert all(path.read_bytes() == content for path, content in local_inputs.items()), 'test inputs changed'


if __name__ == '__main__':
    main()
