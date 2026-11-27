#!/usr/bin/env python3
"""Run the IFC tuple pool lifecycle test with plain and sanitized builds."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


HEADERS = ('airoha_ct_ifc_tuple_words.h', 'airoha_ct_ifc_tuple_pool.h')
TEST = 'ifc_tuple_pool_test.c'
MODES = (('plain', ()), ('sanitized', (
    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
    '-fno-omit-frame-pointer',
)))


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def run(command, timeout):
    environment = os.environ.copy()
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    try:
        process = subprocess.run(command, capture_output=True, timeout=timeout,
                                 env=environment)
        return process.returncode, process.stdout, process.stderr, False
    except subprocess.TimeoutExpired as error:
        return None, error.stdout or b'', error.stderr or b'', True


def write(path, data):
    path.write_bytes(data)


def mode_record(output, name, command, timeout):
    directory = output / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'compile-command.json').write_text(
        json.dumps(command, indent=2) + '\n')
    code, stdout, stderr, timed_out = run(command, timeout)
    write(directory / 'compile-stdout.txt', stdout)
    write(directory / 'compile-stderr.txt', stderr)
    compile_record = {
        'command': command,
        'returncode': code,
        'timed_out': timed_out,
        'stdout_file': 'compile-stdout.txt',
        'stderr_file': 'compile-stderr.txt',
        'stdout_sha256': sha256(stdout),
        'stderr_sha256': sha256(stderr),
    }
    executable = directory / 'test'
    compile_record['executable_sha256'] = (
        sha256(executable.read_bytes()) if code == 0 and executable.is_file()
        else None)
    (directory / 'compile-status.json').write_text(
        json.dumps(compile_record, indent=2) + '\n')
    record = {'name': name, 'compile': compile_record, 'run': None}
    if code != 0 or not executable.is_file():
        return record

    run_command = [str(executable)]
    code, stdout, stderr, timed_out = run(run_command, timeout)
    write(directory / 'stdout.txt', stdout)
    write(directory / 'stderr.txt', stderr)
    run_record = {
        'command': run_command,
        'returncode': code,
        'timed_out': timed_out,
        'stdout_file': 'stdout.txt',
        'stderr_file': 'stderr.txt',
        'stdout_sha256': sha256(stdout),
        'stderr_sha256': sha256(stderr),
    }
    (directory / 'exit-status.json').write_text(
        json.dumps(run_record, indent=2) + '\n')
    record['run'] = run_record
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error('Run without -O; validation requires assertions.')
    parser.add_argument('--source', type=Path, required=True,
                        help='tree containing drivers/net/ethernet/airoha')
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory for logs and summary.json')
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()

    output = args.output.resolve()
    try:
        output.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        print(json.dumps({'passed': False,
                          'error': 'output must not already exist: ' +
                                   str(output)}, indent=2))
        return 1
    source = args.source.resolve() / 'drivers/net/ethernet/airoha'
    clang = shutil.which('clang')
    summary = {
        'passed': False,
        'python': sys.version.split()[0],
        'optimized': not __debug__,
        'source': str(source),
        'output': str(output),
        'compiler': clang,
        'compiler_version': None,
        'timeout_seconds': args.timeout,
        'copied_sources': {},
        'modes': [],
        'outputs_identical': False,
        'streams_compared': ['stdout', 'stderr'],
        'test_result': None,
        'scope': ('Pure IFC tuple pool and tuple word helper lifecycle; '
                  'no kernel, hardware or stock oracle.'),
    }
    summary_path = output / 'summary.json'
    try:
        if not clang:
            raise RuntimeError('clang was not found in PATH')
        version = subprocess.run([clang, '--version'], capture_output=True,
                                 text=True)
        if version.returncode:
            raise RuntimeError('clang --version failed: ' +
                               (version.stderr or version.stdout))
        summary['compiler_version'] = version.stdout.splitlines()[0]
        for name in HEADERS + (TEST,):
            origin = source / name if name in HEADERS else Path(__file__).with_name(name)
            if not origin.is_file():
                raise RuntimeError('missing input: ' + str(origin))
            data = origin.read_bytes()
            write(output / name, data)
            summary['copied_sources'][name] = {
                'source': str(origin),
                'sha256': sha256(data),
            }

        for name, sanitizer in MODES:
            (output / name).mkdir(parents=True)
            command = [clang, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra',
                       '-Werror', '-I', str(output), str(output / TEST), '-o',
                       str(output / name / 'test')]
            command += sanitizer
            summary['modes'].append(mode_record(output, name, command,
                                                args.timeout))

        failed = [mode for mode in summary['modes']
                  if not mode['run'] or mode['run']['returncode'] != 0]
        if failed:
            raise RuntimeError('mode failed: ' +
                               ', '.join(mode['name'] for mode in failed))
        plain, sanitized = summary['modes']
        identical = (
            plain['run']['stdout_sha256'] == sanitized['run']['stdout_sha256'] and
            plain['run']['stderr_sha256'] == sanitized['run']['stderr_sha256'])
        summary['outputs_identical'] = identical
        if not identical:
            raise RuntimeError('plain and sanitized output streams differ')
        stdout = (output / 'plain' / 'stdout.txt').read_text()
        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as error:
            raise RuntimeError('test output is not JSON: ' + str(error)) from error
        summary['test_result'] = result
        if not isinstance(result, dict) or result.get('passed') is not True:
            raise RuntimeError('test did not report passed=true')
        summary['passed'] = True
    except Exception as error:
        summary['error'] = str(error)
        summary_path.write_text(json.dumps(summary, indent=2) + '\n')
        print(json.dumps({'passed': False, 'error': str(error),
                          'summary': str(summary_path)}, indent=2))
        return 1

    summary_path.write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({'passed': True,
                      'cases': summary['test_result'].get('cases'),
                      'fault_cases': summary['test_result'].get('fault_cases'),
                      'recovery_fault_cases': summary['test_result'].get(
                          'recovery_fault_cases'),
                      'outputs_identical': True,
                      'summary': str(summary_path)}, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
