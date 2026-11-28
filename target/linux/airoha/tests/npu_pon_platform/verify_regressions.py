#!/usr/bin/env python3
"""Run the existing CPU fallback and covered Bank1 suites outside the checkout."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
PATCH = '999-zz1-net-airoha-match-pon-full-platform-profile.patch'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source.resolve(), args.output.resolve()
    if output.is_relative_to(REPOSITORY) or output.is_relative_to(source) or source.is_relative_to(output):
        parser.error('output must be new and outside the input trees')
    output.mkdir(parents=True, exist_ok=False)
    tree = output / 'runner-repo'
    tests = tree / 'target/linux/airoha/tests'
    tests.mkdir(parents=True)
    inputs = {}
    for suite in ('native_pair', 'bank1_routes', 'npu_ingress'):
        destination = tests / suite
        destination.mkdir()
        for path in (HERE.parent / suite).iterdir():
            if path.is_file() and path.suffix in ('.py', '.c', '.h', '.inc', '.md'):
                inputs[path] = hashlib.sha256(path.read_bytes()).hexdigest()
                shutil.copyfile(path, destination / path.name)
    patches = tree / 'target/linux/airoha/patches-6.18'
    patches.mkdir()
    for path in sorted((REPOSITORY / 'target/linux/airoha/patches-6.18').glob('*.patch')):
        if path.name > PATCH:
            break
        inputs[path] = hashlib.sha256(path.read_bytes()).hexdigest()
        shutil.copyfile(path, patches / path.name)
    for path in source.rglob('*'):
        if path.is_file():
            inputs[path] = hashlib.sha256(path.read_bytes()).hexdigest()
    shutil.copytree(source, tests / 'native_pair/candidate')
    commands = {
        'cpu-fallback': [sys.executable, '-B', str(tests / 'native_pair/verify_cpu_fallback.py')],
        'covered-routes': [sys.executable, '-B', str(tests / 'bank1_routes/verify_covered.py'),
                           '--source', str(source), '--output', str(tests / 'bank1_routes/out'),
                           '--through-patch', PATCH, '--negative-controls'],
    }
    results = {}
    for name, command in commands.items():
        result = subprocess.run(command, text=True, capture_output=True, timeout=180)
        (output / (name + '.log')).write_text(result.stdout + result.stderr)
        results[name] = result.returncode
        print(name + ': ' + ('PASS' if not result.returncode else 'FAIL'), flush=True)
    for path, expected in inputs.items():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, str(path)
    reports = {}
    for name, path in (
        ('cpu-fallback', tests / 'native_pair/build/cpu-fallback-verification.json'),
        ('covered-routes', tests / 'bank1_routes/out/report.json'),
    ):
        if path.exists():
            reports[name] = json.loads(path.read_text())
    passed = not any(results.values()) and all(report['passed'] for report in reports.values())
    (output / 'report.json').write_text(json.dumps({
        'passed': passed, 'exit_codes': results, 'reports': reports, 'commands': commands,
        'inputs_sha256': {str(path): value for path, value in inputs.items()},
    }, indent=2) + '\n')
    print('report: ' + str(output / 'report.json'), flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
