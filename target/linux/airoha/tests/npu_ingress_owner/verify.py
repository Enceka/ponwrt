#!/usr/bin/env python3
"""Run the production ingress owner I/O and shared guard dependency checks."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import subprocess


DRIVER = Path('drivers/net/ethernet/airoha')
HEADER = 'airoha_npu_ingress_owner.h'
PATCH = '999-ze-net-airoha-connect-pon-npu-ingress-lifecycle.patch'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    tests = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = args.source.resolve() / DRIVER
    patch = tests.parents[1] / 'patches-6.18' / PATCH
    patch_data = patch.read_bytes()
    pattern = r'^--- /dev/null\n\+\+\+ b/' + str(DRIVER / HEADER) + r'\n@@ [^\n]+\n(.*?)(?=^--- |\Z)'
    section = re.search(pattern, patch_data.decode(), re.M | re.S)
    if not section:
        raise ValueError('missing added owner header')
    header = ''.join(line[1:] for line in section[1].splitlines(True) if line.startswith('+'))
    if header.encode() != (source / HEADER).read_bytes():
        raise ValueError('owner header differs from production patch')
    spec = importlib.util.spec_from_file_location('routes', tests.parent / 'bank1_routes/verify.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    originals = {}
    for name in (HEADER, 'airoha_npu_ingress.h', 'airoha_ct_pon_ifc_owner.h',
                 'airoha_ct_pon_ifc_words.h', 'airoha_ct_pon_ifc_cpu.h', 'airoha_ct_ifc.h'):
        originals[name] = (source / name).read_bytes()
        (output / name).write_bytes(originals[name])
    guard = originals['airoha_ct_ifc.h'].decode()
    constants = '\n'.join(line for line in guard.splitlines() if line.startswith('#define CT_IFC_'))
    constants += '\n' + re.search(r'^static const u8 ct_ifc_action_words.*?;', guard, re.M)[0]
    constants += '\n' + re.search(r'^static const struct \{[^}]+\} ct_ifc_guard\[\] = \{.*?^\};',
                                  guard, re.M | re.S)[0] + '\n'
    (output / 'guard_constants.inc').write_text(constants)
    dependency = helper.extract_function(originals['airoha_ct_pon_ifc_cpu.h'].decode(),
                                         'airoha_ct_pon_ifc_dependencies_io')
    (output / 'guard_dependencies.inc').write_text(dependency)
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')

    def run(command, label):
        result = subprocess.run(command, cwd=output, env=environment,
                                capture_output=True, text=True, timeout=120)
        (output / (label + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(label + ':\n' + result.stdout + result.stderr)
        return result.stdout

    build = [args.cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-fno-omit-frame-pointer', '-I', str(output), str(tests / 'owner_io_test.c'),
             '-o', str(output / 'owner_io_test')]
    run(build, 'build')
    result = json.loads(run([str(output / 'owner_io_test')], 'test'))
    mutants = {
        'ignore_write_readback': ('!error && memcmp(actual, words, count * sizeof(*words))', 'false'),
        'lose_pending_owner': ('owner->ingress.pending = true;', 'owner->ppe->ct_pon_ifc.pending = true;'),
        'skip_guard_dependencies': ('return airoha_ct_pon_ifc_dependencies_io(ppe, io);',
                                    '(void)airoha_ct_pon_ifc_dependencies_io; return 0;'),
        'skip_receiver_check': ('!airoha_ct_pon_ifc_route_ready(ppe)',
                                '(false && airoha_ct_pon_ifc_route_ready(ppe))'),
        'ignore_legacy_owner': ('airoha_ct_pon_ifc_busy(ppe)',
                                '(false && airoha_ct_pon_ifc_busy(ppe))'),
        'skip_source_close': ('if (error)\n\t\treturn error;\n\tspin_lock_bh(&ppe_lock);',
                              'spin_lock_bh(&ppe_lock);'),
    }
    caught = {}
    for name, (before, after) in mutants.items():
        if before not in header:
            raise ValueError('missing mutation target: ' + name)
        (output / HEADER).write_text(header.replace(before, after))
        try:
            run(build, name + '-build')
            attempt = subprocess.run([str(output / 'owner_io_test')], cwd=output,
                                     env=environment, capture_output=True, text=True, timeout=120)
            (output / (name + '.log')).write_text(attempt.stdout + attempt.stderr)
            if not attempt.returncode or 'CHECK failed:' not in attempt.stderr:
                raise RuntimeError('mutation survived: ' + name)
            caught[name] = 'runtime assertion'
        finally:
            (output / HEADER).write_text(header)
    run(build, 'build-final')
    if patch.read_bytes() != patch_data:
        raise RuntimeError('production patch changed during run')
    for name, data in originals.items():
        if (source / name).read_bytes() != data:
            raise RuntimeError('source changed during run: ' + name)
    result.update(source=str(args.source.resolve()), patch_sha256=digest(patch_data),
                  source_sha256={name: digest(data) for name, data in originals.items()},
                  test_sha256={name: digest((tests / name).read_bytes())
                               for name in ('verify.py', 'owner_io_test.c')},
                  sanitizers=['address', 'undefined'], mutations=caught)
    (output / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
