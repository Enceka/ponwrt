#!/usr/bin/env python3
"""Exercise production owner notification callers with deterministic fault stubs."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess


FUNCTIONS = {
    'airoha_ct_native_pair.h': (
        'airoha_ct_native_pair_revoke_closed',
        'airoha_ct_native_pair_revoke',
        'airoha_ct_pair_wired_event',
    ),
    'airoha_ppe.c': ('airoha_ppe_ct_bridge_event',),
}


def extract_function(source, name):
    matches = list(re.finditer(
        r'^static [^;{}]*\b' + re.escape(name) + r'\([^;{}]*\)\n\{',
        source, re.MULTILINE))
    if len(matches) != 1:
        raise ValueError('expected one production definition: ' + name)
    start = matches[0].start()
    end = matches[0].end()
    depth = 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise ValueError('unterminated production definition: ' + name)
    return source[start:end] + '\n'


def run(command, directory, label, environment):
    result = subprocess.run(command, capture_output=True, text=True, env=environment)
    (directory / (label + '.log')).write_text(result.stdout + result.stderr)
    return result


def main():
    tests = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path,
                        help='Kernel source root containing the owner notification hooks')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    driver = args.source.resolve() / 'drivers/net/ethernet/airoha'
    functions = {}
    hashes = {}
    for filename, names in FUNCTIONS.items():
        content = (driver / filename).read_bytes()
        hashes[filename] = hashlib.sha256(content).hexdigest()
        for name in names:
            functions[name] = extract_function(content.decode(), name)
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    version = run([args.cc, '--version'], output, 'compiler', environment)
    if version.returncode:
        raise RuntimeError(version.stderr)
    baseline = output / 'baseline'
    baseline.mkdir()

    def build_run(directory, sources):
        (directory / 'events.inc').write_text('\n'.join(sources.values()))
        executable = directory / 'events_test'
        build = run([
            args.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wno-unused-parameter', '-fsanitize=address,undefined',
            '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
            '-I', str(directory), str(tests / 'events_test.c'), '-o', str(executable),
        ], directory, 'build', environment)
        if build.returncode:
            raise RuntimeError('build failed: ' + str(directory) + '\n' + build.stderr)
        return run([str(executable)], directory, 'run', environment)

    result = build_run(baseline, functions)
    if result.returncode:
        raise RuntimeError('baseline failed:\n' + result.stdout + result.stderr)
    summary = json.loads(result.stdout)
    mutants = {
        'bridge_skip_cleanup_on_owner_error': (
            'airoha_ppe_ct_bridge_event',
            'err = airoha_npu_owner_notify(ppe, NULL);',
            'err = airoha_npu_owner_notify(ppe, NULL);\n\tif (err) goto unlock;'),
        'bridge_overwrite_first_error': (
            'airoha_ppe_ct_bridge_event', 'if (err && !info->err)', 'if (err)'),
        'bridge_skip_rows_on_owner_eagain': (
            'airoha_ppe_ct_bridge_event',
            'cleanup_failed |= ppe->ct_bridge_failed || ppe->ct_stopping;',
            'cleanup_failed |= !!err || ppe->ct_bridge_failed || ppe->ct_stopping;'),
        'native_ignore_incomplete_owner_close': (
            'airoha_ct_native_pair_revoke', 'if (err)', 'if (false)'),
        'native_notify_during_internal_stop': (
            'airoha_ct_native_pair_revoke', 'if (ppe->ct_host_ppe)', 'if (true)'),
        'native_accept_unquiesced_generic_owner': (
            'airoha_ct_native_pair_revoke_closed', 'return -EAGAIN;', 'return 0;'),
        'wired_filter_pon_before_notify': (
            'airoha_ct_pair_wired_event', 'if (revoke && ppe->ct_host_ppe)',
            'if (dev != airoha_ct_pair_lan1(ppe)) goto out;\n'
            '\tif (revoke && ppe->ct_host_ppe)'),
        'bridge_skip_failclose_after_native_guard_error': (
            'airoha_ppe_ct_bridge_event',
            '\t\tif (err) {\n\t\t\tif (!ppe->ct_bridge_failed)\n'
            '\t\t\t\tairoha_ppe_ct_bridge_fail_closed(ppe);\n'
            '\t\t\tcleanup_failed = true;\n\t\t}', ''),
    }
    detected = []
    for name, (function, original, replacement) in mutants.items():
        if functions[function].count(original) != 1:
            raise RuntimeError('mutation must match exactly once: ' + name)
        modified = dict(functions)
        modified[function] = modified[function].replace(original, replacement, 1)
        directory = output / name
        directory.mkdir()
        result = build_run(directory, modified)
        if result.returncode != 1 or 'CHECK failed:' not in result.stderr:
            raise RuntimeError('negative control did not fail its assertion: ' + name)
        detected.append({'name': name, 'failure': result.stderr.strip()})
    for filename, expected in hashes.items():
        if hashlib.sha256((driver / filename).read_bytes()).hexdigest() != expected:
            raise RuntimeError('source changed during testing: ' + filename)
    report = {
        'passed': True,
        'source': str(driver), 'sha256': hashes,
        'test_sha256': {name: hashlib.sha256((tests / name).read_bytes()).hexdigest()
                       for name in ('verify.py', 'events_test.c')},
        'functions': list(functions), 'baseline': summary,
        'negative_controls': detected,
        'sanitizers': ['address', 'undefined'],
        'scope': 'Real event callers and native cleanup; owner notify, MMIO and kernel primitives are stubbed.',
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'scenarios': summary['scenarios'], 'checks': summary['checks'],
                      'negative_controls': len(detected), 'report': str(output / 'report.json')}))


if __name__ == '__main__':
    main()
